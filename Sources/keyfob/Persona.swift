import CryptoKit
import LocalAuthentication
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

  /// keyfob's copy named `app`, refreshed when keyfob changes. A real copy
  /// (an APFS clone, so cheap), not a hard link: hard links share one vnode
  /// and macOS may title the sheet with whichever name it saw last.
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
    try manager.copyItem(atPath: source, toPath: temporary)
    try manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: temporary)
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
      case let app = Caller.parent.displayApp,
      fileName(app) != currentName,
      let path = try? executable(named: app)
    else { return }
    setenv("KEYFOB_PERSONA", app, 1)
    let argv = CommandLine.arguments.map { strdup($0) } + [nil]
    execv(path, argv)
    // execv only returns on failure: carry on as keyfob
  }

  // MARK: Unlocking keys

  /// What a child does with an unlocked Secure Enclave key.
  enum Mode: String {
    /// ECDSA signature (SSH), payload = data to sign
    case sign
    /// ECDH (git credentials, age), payload = peer public key, x963
    case agree
  }

  enum Outcome: UInt8 {
    case approved, reused, expired, denied
  }

  /// Uses a Secure Enclave key in a child process started from the copy
  /// named after the app, so the Touch ID sheet carries the app's name.
  /// With a grant, the scope's long-lived child reuses its approval until the
  /// grant ends; without one, a fresh child asks and exits.
  static func unlock(
    _ mode: Mode, handle: Data, protection: Protection, payload: Data, reason: String,
    as app: String, grant: Reuse.Grant?
  ) throws -> (result: Data, reused: Bool) {
    guard let grant else {
      let child = try Unlocker(mode: mode, handle: handle, protection: protection, seconds: 0, app: app)
      defer { child.stop() }
      let (outcome, result) = child.request(payload, reason: reason)
      guard outcome == .approved, let result else { throw KeyfobError("denied") }
      return (result, false)
    }
    // A child whose approval ended answers `expired`: retry with a new one
    for _ in 0..<2 {
      let child = try Unlocker.running(
        grant: grant, mode: mode, handle: handle, protection: protection, app: app)
      let (outcome, result) = child.request(payload, reason: reason)
      switch outcome {
      case .approved, .reused:
        if let result { return (result, outcome == .reused) }
        Unlocker.stop(scope: grant.scope)
      case .expired:
        Unlocker.stop(scope: grant.scope)
      case .denied:
        Unlocker.stop(scope: grant.scope)
        throw KeyfobError("denied")
      }
    }
    throw KeyfobError("unlocker did not respond")
  }

  /// Child side (`__unlock MODE PROTECTION SECONDS`): reads the key handle,
  /// then answers framed (reason, payload) requests. The first asks for
  /// Touch ID (or the password for normal keys); later ones reuse that
  /// approval for SECONDS, after which the child exits.
  static func serveUnlocks(mode: Mode, protection: Protection, seconds: TimeInterval) throws {
    let input = FileHandle.standardInput
    let output = FileHandle.standardOutput
    guard let handle = Frame.read(from: input) else { return }
    // Dangerous keys ask every time, whoever starts this
    let seconds = protection == .dangerous ? 0 : min(max(seconds, 0), 600)
    var unlocked: ((Data) throws -> Data)?
    var deadline = Date.distantFuture

    func respond(_ outcome: Outcome, _ result: Data = Data()) {
      try? output.write(contentsOf: Data([outcome.rawValue]))
      Frame.write(result, to: output)
    }

    while let reason = Frame.read(from: input), let payload = Frame.read(from: input) {
      if Date() > deadline {
        respond(.expired)
        return
      }
      do {
        if let unlocked {
          respond(.reused, try unlocked(payload))
          continue
        }
        let context = SecureEnclaveKeys.context(reason: String(decoding: reason, as: UTF8.self))
        if protection != .none { try authenticate(context, biometricOnly: protection != .normal) }
        let use: (Data) throws -> Data
        switch mode {
        case .sign:
          let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: handle, authenticationContext: context)
          use = { try key.signature(for: $0).rawRepresentation }
        case .agree:
          let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: handle, authenticationContext: context)
          use = {
            try key.sharedSecretFromKeyAgreement(
              with: P256.KeyAgreement.PublicKey(x963Representation: $0)
            ).withUnsafeBytes { Data($0) }
          }
        }
        let result = try use(payload)
        respond(.approved, result)
        guard seconds > 0 else { return }
        unlocked = use
        deadline = Date().addingTimeInterval(seconds)
        // Do not keep an unlocked key around after the approval ends
        DispatchQueue.global().asyncAfter(deadline: .now() + seconds) { exit(0) }
      } catch {
        respond(.denied)
        return
      }
    }
  }

  /// Touch ID (or password) once, so the context can use the key without
  /// asking again. Touch ID only keys need a biometric evaluation.
  private static func authenticate(_ context: LAContext, biometricOnly: Bool) throws {
    let done = DispatchSemaphore(value: 0)
    var failure: Error?
    context.evaluatePolicy(
      biometricOnly ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication,
      localizedReason: context.localizedReason
    ) { success, error in
      if !success { failure = error ?? KeyfobError("authentication failed") }
      done.signal()
    }
    done.wait()
    if let failure { throw failure }
  }
}

/// A running `__unlock` child. The agent keeps one per reuse scope; callers
/// serialize access (the agent handles one key use at a time).
final class Unlocker {
  private static var children: [String: Unlocker] = [:]

  private let process: Process
  private let input: FileHandle
  private let output: FileHandle
  private var summary = ""
  private var approvedAt: Date?
  private var seconds: TimeInterval = 0

  fileprivate init(mode: Persona.Mode, handle: Data, protection: Protection, seconds: TimeInterval, app: String)
    throws
  {
    process = Process()
    process.executableURL = URL(fileURLWithPath: try Persona.executable(named: app))
    process.arguments = ["__unlock", mode.rawValue, protection.rawValue, String(Int(seconds))]
    let inputPipe = Pipe()
    let outputPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outputPipe
    try process.run()
    input = inputPipe.fileHandleForWriting
    output = outputPipe.fileHandleForReading
    self.seconds = seconds
    Frame.write(handle, to: input)
  }

  fileprivate static func running(
    grant: Reuse.Grant, mode: Persona.Mode, handle: Data, protection: Protection, app: String
  ) throws -> Unlocker {
    if let child = children[grant.scope], child.process.isRunning { return child }
    let child = try Unlocker(
      mode: mode, handle: handle, protection: protection, seconds: grant.seconds, app: app)
    child.summary = grant.summary
    children[grant.scope] = child
    return child
  }

  static func stop(scope: String) {
    children.removeValue(forKey: scope)?.stop()
  }

  /// `keyfob lock`, screen lock and sleep: forget every approval.
  static func stopAll() {
    children.values.forEach { $0.stop() }
    children.removeAll()
  }

  /// Approvals still in force, for `keyfob status`.
  static var active: [String] {
    children.values.compactMap { child in
      guard child.process.isRunning, let approvedAt = child.approvedAt else { return nil }
      let left = Int(child.seconds - Date().timeIntervalSince(approvedAt))
      return left > 0 ? "\(child.summary) (\(left)s left)" : nil
    }.sorted()
  }

  fileprivate func stop() {
    if process.isRunning { process.terminate() }
  }

  fileprivate func request(_ payload: Data, reason: String) -> (Persona.Outcome, Data?) {
    Frame.write(Data(reason.utf8), to: input)
    Frame.write(payload, to: input)
    guard let status = Frame.readExactly(1, from: output),
      let outcome = Persona.Outcome(rawValue: status[0]),
      let result = Frame.read(from: output)
    else { return (.expired, nil) }
    if outcome == .approved { approvedAt = Date() }
    return (outcome, result.isEmpty ? nil : result)
  }
}

/// Length-prefixed messages between the agent and its children.
enum Frame {
  static func write(_ data: Data, to handle: FileHandle) {
    var length = UInt32(data.count).bigEndian
    try? handle.write(contentsOf: Data(bytes: &length, count: 4) + data)
  }

  static func read(from handle: FileHandle) -> Data? {
    guard let header = readExactly(4, from: handle) else { return nil }
    let length = header.reduce(0) { $0 << 8 | Int($1) }
    guard length <= 1 << 20 else { return nil }
    return length == 0 ? Data() : readExactly(length, from: handle)
  }

  static func readExactly(_ count: Int, from handle: FileHandle) -> Data? {
    var data = Data()
    while data.count < count {
      guard let chunk = try? handle.read(upToCount: count - data.count), !chunk.isEmpty else {
        return nil
      }
      data.append(chunk)
    }
    return data
  }
}
