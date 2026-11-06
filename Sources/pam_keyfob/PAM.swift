import Darwin
import Foundation
import LocalAuthentication

// PAM module for sudo: Touch ID with a sheet saying what runs as root, where,
// and who asked:
//
//   sudo is trying to run as root:
//   🔧 brew install foo
//   📁 ~/Projects/demo
//   🤖 requested by claude.
//
// Use it as `sufficient` before the password, so denying, cancelling or any
// failure falls through to the next module and sudo keeps working.

private let PAM_SUCCESS: Int32 = 0
private let PAM_AUTH_ERR: Int32 = 9
private let PAM_IGNORE: Int32 = 25

/// What Caller.swift (shared with keyfob) needs from the keyfob binary.
enum Persona {
  static var currentName: String { "sudo" }
  static func fileName(_ app: String) -> String { app }
}

enum Paths {
  static var home: URL { URL(fileURLWithPath: invokingHome).appendingPathComponent(".config/keyfob") }
  static func exists(_ url: URL) -> Bool { FileManager.default.fileExists(atPath: url.path) }

  /// sudo is setuid root; the real uid is the user who ran it
  static var invokingHome: String {
    getpwuid(getuid()).map { String(cString: $0.pointee.pw_dir) } ?? NSHomeDirectory()
  }
}

@_cdecl("pam_sm_authenticate")
public func pam_sm_authenticate(
  _ pamh: OpaquePointer?, _ flags: Int32, _ argc: Int32,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> Int32 {
  // `sudo -A` asks through a program: leave it to the next module
  let arguments = ProcessInfo.processInfo.arguments
  if arguments.contains("-A") || arguments.contains("--askpass") { return PAM_IGNORE }

  // Touch ID or Apple Watch, skipping the user check (sudo runs as root):
  // the private policy Apple's pam_tid uses, else plain Touch ID
  let policy = LAPolicy(rawValue: 0x3f0) ?? .deviceOwnerAuthenticationWithBiometrics
  let context = LAContext()
  context.localizedCancelTitle = "Deny"
  guard context.canEvaluatePolicy(policy, error: nil) else { return PAM_IGNORE }

  let sudo = Caller(pid: getpid())
  let reason = SudoRequest(sudo: sudo, requester: Caller(pid: getppid())).reason
  let done = DispatchSemaphore(value: 0)
  var approved = false
  context.evaluatePolicy(policy, localizedReason: reason) { success, _ in
    approved = success
    done.signal()
  }
  done.wait()
  SudoRequest.log(reason, caller: sudo, approved: approved)
  return approved ? PAM_SUCCESS : PAM_AUTH_ERR
}

@_cdecl("pam_sm_setcred")
public func pam_sm_setcred(
  _ pamh: OpaquePointer?, _ flags: Int32, _ argc: Int32,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> Int32 {
  PAM_IGNORE
}

@_cdecl("pam_sm_acct_mgmt")
public func pam_sm_acct_mgmt(
  _ pamh: OpaquePointer?, _ flags: Int32, _ argc: Int32,
  _ argv: UnsafePointer<UnsafePointer<CChar>?>?
) -> Int32 {
  PAM_IGNORE
}

/// The sudo invocation, read from sudo's own argv and working directory.
struct SudoRequest {
  let reason: String

  init(sudo: Caller, requester: Caller) {
    let process = sudo.chain.first
    var target: String?
    var shell = false
    var command: [String] = []
    let valueOptions: Set<String> = [
      "-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-T", "-U", "--user", "--group",
      "--chdir", "--host", "--prompt", "--role", "--type", "--command-timeout",
      "--other-user", "--close-from",
    ]
    var rest = (process?.arguments.dropFirst() ?? [])[...]
    while let argument = rest.popFirst() {
      if argument == "--" {
        command = Array(rest)
        break
      }
      guard argument.hasPrefix("-") else {
        command = [argument] + rest
        break
      }
      let option = String(argument.prefix { $0 != "=" })
      if ["-i", "-s", "--login", "--shell"].contains(option) { shell = true }
      if option == "--user", let equals = argument.firstIndex(of: "=") {
        target = String(argument[argument.index(after: equals)...])
      } else if argument.hasPrefix("-u"), argument.count > 2 {
        target = String(argument.dropFirst(2))
      } else if valueOptions.contains(argument) {
        let value = rest.popFirst()
        if argument == "-u" || argument == "--user" { target = value }
      }
    }

    let user = target ?? "root"
    let title =
      !command.isEmpty ? "run as \(user)" : shell ? "open a shell as \(user)" : "authenticate as \(user)"
    let app = requester.app ?? "unknown"
    let who = requester.initiatorLabel.map { "\($0) in \(app)" } ?? app
    let facts = [
      command.isEmpty ? nil : "🔧 " + Caller.clean(command.joined(separator: " ")),
      process?.workingDirectory.map { "📁 " + Caller.clean(Caller.displayPath($0)) },
      "🤖 requested by " + Caller.clean(who),
    ].compactMap { $0 }
    reason = ([title + ":"] + facts).joined(separator: "\n")
  }

  /// Into the invoking user's keyfob log, owned by them even though sudo
  /// runs as root.
  static func log(_ reason: String, caller: Caller, approved: Bool) {
    let path = Paths.invokingHome + "/Library/Logs/keyfob.log"
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let outcome = approved ? "allowed" : "denied"
    let text = Caller.clean("sudo " + reason.split(separator: "\n").joined(separator: " "), limit: 300)
    let line = "\(timestamp) \(outcome) \(text) [\(caller.detail)]\n"
    let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { return }
    defer { close(fd) }
    _ = fchown(fd, getuid(), getgid())
    _ = line.utf8CString.withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count - 1) }
  }
}
