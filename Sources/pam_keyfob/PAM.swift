import Darwin
import Foundation
import LocalAuthentication
import Security

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
  // sudo -n/-S/-A wants no sheet from us, and without a GUI session (sudo
  // over ssh) a sheet would wait on a screen nobody sees: next module
  let arguments = CommandLine.arguments
  if SudoRequest.parse(arguments).nonInteractive || !hasGraphicSession { return PAM_IGNORE }

  // Only vouch for the user who ran sudo: with `targetpw`/`rootpw` PAM asks
  // about another account, which this user's finger must not unlock
  guard let user = requestedUser(pamh), user == invokingUser else { return PAM_IGNORE }

  // Touch ID or Apple Watch, skipping the user check (sudo runs as root):
  // the private policy Apple's pam_tid uses, else plain Touch ID
  let policy = LAPolicy(rawValue: 0x3f0) ?? .deviceOwnerAuthenticationWithBiometrics
  let context = LAContext()
  context.localizedCancelTitle = "Deny"
  guard context.canEvaluatePolicy(policy, error: nil) else { return PAM_IGNORE }

  let sudo = Caller(pid: getpid())
  let reason = SudoRequest(arguments: arguments, sudo: sudo, requester: Caller(pid: getppid())).reason
  let done = DispatchSemaphore(value: 0)
  var approved = false
  context.evaluatePolicy(policy, localizedReason: reason) { success, _ in
    approved = success
    done.signal()
  }
  // An unanswered sheet must not hold sudo: give up and fall through
  if done.wait(timeout: .now() + 120) == .timedOut {
    context.invalidate()
    approved = false
  }
  SudoRequest.log(reason, caller: sudo, approved: approved)
  return approved ? PAM_SUCCESS : PAM_AUTH_ERR
}

/// Whether this security session has a screen (not an ssh login).
private var hasGraphicSession: Bool {
  var session = SecuritySessionId()
  var attributes = SessionAttributeBits()
  guard SessionGetInfo(callerSecuritySession, &session, &attributes) == errSecSuccess else {
    return false
  }
  return attributes.contains(.sessionHasGraphicAccess)
}

private let PAM_USER: Int32 = 2

/// The account PAM authenticates. pam_get_item comes from libpam, which sudo
/// has loaded; looked up at run time so the module does not link it.
private func requestedUser(_ pamh: OpaquePointer?) -> String? {
  typealias GetItem = @convention(c) (
    OpaquePointer?, Int32, UnsafeMutablePointer<UnsafeRawPointer?>
  ) -> Int32
  guard let pamh, let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "pam_get_item")
  else { return nil }
  var item: UnsafeRawPointer?
  guard unsafeBitCast(symbol, to: GetItem.self)(pamh, PAM_USER, &item) == PAM_SUCCESS, let item
  else { return nil }
  return String(cString: item.assumingMemoryBound(to: CChar.self))
}

/// sudo is setuid root; the real uid is the user who ran it
private var invokingUser: String? {
  getpwuid(getuid()).map { String(cString: $0.pointee.pw_name) }
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

  /// `arguments`: sudo's own argv, from this process (the module runs inside
  /// sudo), not the kernel's argument dump, which an empty argv[0] can shift.
  init(arguments: [String], sudo: Caller, requester: Caller) {
    let process = sudo.chain.first
    let parsed = SudoRequest.parse(arguments)
    let target = parsed.user
    let shell = parsed.shell
    let command = parsed.command

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

  /// Into the invoking user's keyfob log, best effort. The path is under the
  /// user's control, so it is opened with the user's own rights (never as
  /// root: a link to a root file must not be written or handed over), without
  /// blocking (a FIFO must not hold sudo), and only if it is a regular file.
  static func log(_ reason: String, caller: Caller, approved: Bool) {
    let path = Paths.invokingHome + "/Library/Logs/keyfob.log"
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let outcome = approved ? "allowed" : "denied"
    let text = Caller.clean("sudo " + reason.split(separator: "\n").joined(separator: " "), limit: 300)
    let line = "\(timestamp) \(outcome) \(text) [\(caller.detail)]\n"

    let rootEffective = geteuid() == 0
    if rootEffective {
      guard setegid(getgid()) == 0, seteuid(getuid()) == 0 else { return }
    }
    defer {
      if rootEffective {
        _ = seteuid(0)
        _ = setegid(0)
      }
    }
    let fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0o600)
    guard fd >= 0 else { return }
    defer { close(fd) }
    var status = stat()
    guard fstat(fd, &status) == 0, status.st_mode & S_IFMT == S_IFREG, status.st_uid == getuid()
    else { return }
    _ = line.utf8CString.withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count - 1) }
  }
}

extension SudoRequest {
  struct Parsed {
    var user: String?
    var shell = false
    var command: [String] = []
    /// -n, -S, -A: no interactive authentication wanted from us
    var nonInteractive = false
  }

  /// sudo's options the way its getopt reads them: clustered short flags
  /// (`-Hu root`, `-uroot`), long options with `=` or a separate value.
  static func parse(_ arguments: [String]) -> Parsed {
    var parsed = Parsed()
    let valueLetters = Set("ugCDhprtTU")
    let valueLong: Set<String> = [
      "--user", "--group", "--chdir", "--host", "--prompt", "--role", "--type",
      "--command-timeout", "--other-user", "--close-from",
    ]
    var rest = arguments.dropFirst()[...]
    while let argument = rest.popFirst() {
      if argument == "--" {
        parsed.command = Array(rest)
        break
      }
      guard argument.hasPrefix("-"), argument.count > 1 else {
        parsed.command = [argument] + rest
        break
      }
      if argument.hasPrefix("--") {
        let option = String(argument.prefix { $0 != "=" })
        var value: String?
        if let equals = argument.firstIndex(of: "=") {
          value = String(argument[argument.index(after: equals)...])
        } else if valueLong.contains(option) {
          value = rest.popFirst()
        }
        if option == "--user" { parsed.user = value }
        if ["--login", "--shell"].contains(option) { parsed.shell = true }
        if ["--non-interactive", "--stdin", "--askpass"].contains(option) { parsed.nonInteractive = true }
        continue
      }
      var letters = argument.dropFirst()[...]
      while let letter = letters.popFirst() {
        if valueLetters.contains(letter) {
          let value = letters.isEmpty ? rest.popFirst() : String(letters)
          if letter == "u" { parsed.user = value }
          break
        }
        if letter == "i" || letter == "s" { parsed.shell = true }
        if letter == "n" || letter == "S" || letter == "A" { parsed.nonInteractive = true }
      }
    }
    return parsed
  }
}
