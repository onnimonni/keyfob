import CryptoKit
import Darwin
import Foundation

/// macOS titles the Touch ID sheet with the file name of the executable
/// ("<name> is trying to …"). To make it read "Claude Code is trying to …",
/// keyfob runs a copy of itself named after the requesting app.
///
/// This is cosmetic: any program can name its executable anything, so the
/// title was never proof of who is asking. The audit log has the real chain.
enum Persona {
  static var directory: URL { Paths.home.appendingPathComponent("bin") }

  /// This process's executable, resolved by the kernel.
  static var ownPath: String {
    var buffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    guard proc_pidpath(getpid(), &buffer, UInt32(buffer.count)) > 0 else {
      return CommandLine.arguments[0]
    }
    return String(cString: buffer)
  }

  /// The name macOS shows for this process.
  static var currentName: String { URL(fileURLWithPath: ownPath).lastPathComponent }

  static func fileName(_ app: String) -> String {
    let name = app.replacingOccurrences(of: "/", with: "-")
    return name.hasPrefix(".") ? "_" + name : name
  }

  /// keyfob's copy named `app`: a hard link when on the same volume, else a
  /// copy (the nix store is its own volume). Refreshed when keyfob changes.
  static func executable(named app: String) throws -> String {
    let source = ownPath
    let target = directory.appendingPathComponent(fileName(app)).path
    let manager = FileManager.default
    if manager.fileExists(atPath: target), manager.contentsEqual(atPath: source, andPath: target) {
      return target
    }
    try Paths.ensureDirectory(directory)
    let temporary = target + ".\(getpid()).tmp"
    unlink(temporary)
    if link(source, temporary) != 0 {
      try manager.copyItem(atPath: source, toPath: temporary)
      try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: temporary)
    }
    guard rename(temporary, target) == 0 else {
      unlink(temporary)
      throw KeyfobError("cannot install \(target): \(String(cString: strerror(errno)))")
    }
    return target
  }

  /// Short-lived modes (git credential helper, age plugin) replace themselves
  /// with the copy named after the caller's app before showing Touch ID.
  /// Must run before stdin is read; argv is kept so dispatch still works.
  static func becomeCallerApp() {
    guard ProcessInfo.processInfo.environment["KEYFOB_PERSONA"] == nil,
      let app = Caller.parent.app,
      fileName(app) != currentName,
      let path = try? executable(named: app)
    else { return }
    setenv("KEYFOB_PERSONA", app, 1)
    let argv = CommandLine.arguments.map { strdup($0) } + [nil]
    execv(path, argv)
    // execv only returns on failure: carry on as keyfob
  }

  /// The SSH agent is long-running, so each signature happens in a child
  /// process started from the copy named after the app.
  static func sign(_ data: Data, reason: String, as app: String) throws
    -> P256.Signing.ECDSASignature
  {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: try executable(named: app))
    process.arguments = ["__sign", reason]
    let input = Pipe()
    let output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    try process.run()
    input.fileHandleForWriting.write(data)
    try input.fileHandleForWriting.close()
    let signature = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else { throw KeyfobError("signing was denied") }
    return try P256.Signing.ECDSASignature(rawRepresentation: signature)
  }

  /// Child side of `sign`: data on stdin, raw signature on stdout.
  static func signChild(reason: String) throws {
    let data = FileHandle.standardInput.readDataToEndOfFile()
    let signature = try SecureEnclaveKeys.loadSigningKey(reason: reason).signature(for: data)
    FileHandle.standardOutput.write(signature.rawRepresentation)
  }
}
