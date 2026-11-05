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

  // MARK: SSH signatures

  /// How long one approval of a normal SSH key lasts, per app and key.
  static let reuseSeconds: TimeInterval = 300

  enum Outcome: UInt8 {
    case approved, reused, expired, denied
  }

  /// The SSH agent is long-running, so signatures happen in child processes
  /// started from the copy named after the app. Dangerous keys get a fresh
  /// child (and Touch ID) every time; normal keys keep one child per app and
  /// key that reuses its approval for `reuseSeconds`.
  static func sign(_ data: Data, with key: Key, reason: String, as app: String) throws
    -> (signature: P256.Signing.ECDSASignature, reused: Bool)
  {
    if key.protection == .dangerous {
      let process = Process()
      process.executableURL = URL(fileURLWithPath: try executable(named: app))
      process.arguments = ["__sign", key.name, reason]
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
      return (try P256.Signing.ECDSASignature(rawRepresentation: signature), false)
    }

    // A child whose approval expired answers `expired`: retry with a new one
    for _ in 0..<2 {
      let signer = try Signer.running(app: app, key: key)
      let (outcome, signature) = signer.sign(data, reason: reason)
      switch outcome {
      case .approved, .reused:
        if let signature { return (signature, outcome == .reused) }
        Signer.stop(app: app, key: key)
      case .expired:
        Signer.stop(app: app, key: key)
      case .denied:
        Signer.stop(app: app, key: key)
        throw KeyfobError("signing was denied")
      }
    }
    throw KeyfobError("signer did not respond")
  }

  /// Child for dangerous keys: data on stdin, raw signature on stdout.
  static func signOnce(keyName: String, reason: String) throws {
    guard let key = Key.named(.ssh, keyName) else { throw KeyfobError("no SSH key '\(keyName)'") }
    let data = FileHandle.standardInput.readDataToEndOfFile()
    let signature = try key.loadSigningKey(context: SecureEnclaveKeys.context(reason: reason))
      .signature(for: data)
    FileHandle.standardOutput.write(signature.rawRepresentation)
  }

  /// Child for normal keys: answers framed (reason, data) requests. The first
  /// one asks for Touch ID or the password; later ones reuse that approval
  /// until `reuseSeconds` have passed, then the child answers `expired`.
  static func serveSignatures(keyName: String, reuseSeconds: TimeInterval) throws {
    guard let key = Key.named(.ssh, keyName) else { throw KeyfobError("no SSH key '\(keyName)'") }
    let input = FileHandle.standardInput
    let output = FileHandle.standardOutput
    var unlocked: SecureEnclave.P256.Signing.PrivateKey?
    var deadline = Date.distantFuture

    func respond(_ outcome: Outcome, _ signature: P256.Signing.ECDSASignature? = nil) {
      output.write(Data([outcome.rawValue]))
      Frame.write(signature?.rawRepresentation ?? Data(), to: output)
    }

    while let reason = Frame.read(from: input), let data = Frame.read(from: input) {
      if Date() > deadline {
        respond(.expired)
        return
      }
      do {
        if let unlocked {
          respond(.reused, try unlocked.signature(for: data))
          continue
        }
        let context = SecureEnclaveKeys.context(reason: String(decoding: reason, as: UTF8.self))
        if key.protection != .none { try authenticate(context) }
        let privateKey = try key.loadSigningKey(context: context)
        let signature = try privateKey.signature(for: data)
        unlocked = privateKey
        deadline = Date().addingTimeInterval(reuseSeconds)
        respond(.approved, signature)
      } catch {
        respond(.denied)
        return
      }
    }
  }

  /// Touch ID or password once, so the context can sign without asking again.
  private static func authenticate(_ context: LAContext) throws {
    let done = DispatchSemaphore(value: 0)
    var failure: Error?
    context.evaluatePolicy(
      .deviceOwnerAuthentication, localizedReason: context.localizedReason
    ) { success, error in
      if !success { failure = error ?? KeyfobError("authentication failed") }
      done.signal()
    }
    done.wait()
    if let failure { throw failure }
  }
}

/// A running `__signer` child, kept by the SSH agent per app and key.
final class Signer {
  private static var children: [String: Signer] = [:]

  private let process: Process
  private let input: FileHandle
  private let output: FileHandle

  private init(app: String, key: Key) throws {
    process = Process()
    process.executableURL = URL(fileURLWithPath: try Persona.executable(named: app))
    process.arguments = ["__signer", key.name, String(Int(Persona.reuseSeconds))]
    let inputPipe = Pipe()
    let outputPipe = Pipe()
    process.standardInput = inputPipe
    process.standardOutput = outputPipe
    try process.run()
    input = inputPipe.fileHandleForWriting
    output = outputPipe.fileHandleForReading
  }

  /// Callers serialize access (the agent signs one request at a time).
  static func running(app: String, key: Key) throws -> Signer {
    let id = "\(app)\u{0}\(key.name)"
    if let signer = children[id], signer.process.isRunning { return signer }
    let signer = try Signer(app: app, key: key)
    children[id] = signer
    return signer
  }

  static func stop(app: String, key: Key) {
    children.removeValue(forKey: "\(app)\u{0}\(key.name)")?.process.terminate()
  }

  func sign(_ data: Data, reason: String) -> (Persona.Outcome, P256.Signing.ECDSASignature?) {
    Frame.write(Data(reason.utf8), to: input)
    Frame.write(data, to: input)
    guard let status = Frame.readExactly(1, from: output), let outcome = Persona.Outcome(rawValue: status[0]),
      let raw = Frame.read(from: output)
    else { return (.expired, nil) }
    return (outcome, raw.isEmpty ? nil : try? P256.Signing.ECDSASignature(rawRepresentation: raw))
  }
}

/// Length-prefixed messages between the agent and its signer children.
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
