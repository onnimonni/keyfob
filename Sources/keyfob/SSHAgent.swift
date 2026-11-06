import AppKit
import CryptoKit
import Darwin
import Foundation

/// ssh-agent (draft-miller-ssh-agent) serving the keyfob SSH keys, and the
/// broker for every other Secure Enclave key use: git credentials and age
/// decryption come in as keyfob extensions, so all of them share one reuse
/// policy (see Reuse) and one `keyfob lock`.
final class SSHAgent {
  enum Message: UInt8 {
    case failure = 5
    case success = 6
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case `extension` = 27
  }

  /// keyfob's own agent extensions (SSH_AGENTC_EXTENSION names)
  enum Extension {
    /// purpose ("age"), key handle, peer public key, context| "age"), key handle, peer public key, context
    static let agree = "keyfob-agree@flaky.build"
    /// credential file id (URL) and its contents; answer: verified plaintext
    static let credential = "keyfob-credential@flaky.build"
    static let lock = "keyfob-lock@flaky.build"
    static let status = "keyfob-status@flaky.build"
  }

  /// Idle or slow clients each hold a thread; cap them.
  private static let maxConnections = 64
  private let connectionLock = NSLock()
  private var connections = 0

  private let socketPath: String
  /// One Touch ID sheet at a time; also guards the Unlocker children
  private let keyLock = NSLock()

  init(socketPath: String) {
    self.socketPath = socketPath
  }

  func run() throws -> Never {
    signal(SIGPIPE, SIG_IGN)
    let server = try listen()
    log("listening on \(socketPath)")
    Thread.detachNewThread { [self] in acceptLoop(server) }

    // Forget every approval when the screen locks or the Mac sleeps
    let forget: (Notification) -> Void = { [self] notification in
      Unlocker.stopAll()
      log("approvals cleared: \(notification.name.rawValue)")
    }
    DistributedNotificationCenter.default().addObserver(
      forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: nil,
      using: forget)
    NSWorkspace.shared.notificationCenter.addObserver(
      forName: NSWorkspace.willSleepNotification, object: nil, queue: nil, using: forget)
    // Fast user switching away from this account
    NSWorkspace.shared.notificationCenter.addObserver(
      forName: NSWorkspace.sessionDidResignActiveNotification, object: nil, queue: nil,
      using: forget)
    while true { RunLoop.main.run() }
  }

  private func listen() throws -> Int32 {
    // Not ensureDirectory: the socket may live in a shared directory like /tmp
    try FileManager.default.createDirectory(
      at: URL(fileURLWithPath: socketPath).deletingLastPathComponent(),
      withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    unlink(socketPath)

    let server = socket(AF_UNIX, SOCK_STREAM, 0)
    guard server >= 0 else { throw posixError("socket") }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(socketPath.utf8)
    guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
      throw KeyfobError("socket path too long: \(socketPath)")
    }
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in
      buffer.copyBytes(from: pathBytes)
    }
    let previousMask = umask(0o177)
    let bound = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        bind(server, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    umask(previousMask)
    guard bound == 0 else { throw posixError("bind \(socketPath)") }
    guard Darwin.listen(server, 16) == 0 else { throw posixError("listen") }
    return server
  }

  private func acceptLoop(_ server: Int32) {
    while true {
      let client = accept(server, nil, nil)
      if client < 0 {
        // EMFILE and friends: back off instead of spinning
        usleep(100_000)
        continue
      }
      connectionLock.lock()
      let accepted = connections < SSHAgent.maxConnections
      if accepted { connections += 1 }
      connectionLock.unlock()
      guard accepted else {
        close(client)
        continue
      }
      // Clients send their next message promptly (ssh connects per auth);
      // an idle or stalled one must not hold a connection slot forever
      SSHAgent.setTimeout(client, SO_RCVTIMEO, seconds: 120)
      SSHAgent.setTimeout(client, SO_SNDTIMEO, seconds: 30)
      Thread.detachNewThread { [self] in
        serve(client)
        close(client)
        connectionLock.lock()
        connections -= 1
        connectionLock.unlock()
      }
    }
  }

  /// One client connection. ssh (8.9+) sends session-bind@openssh.com before
  /// using the agent, with a flag when it is relaying a forwarded agent.
  private final class Connection {
    /// Recomputed for every request: a connection kept open must not keep the
    /// identity of a session that has ended
    var peer: Caller
    var bound = false
    var forwarded = false
    /// From session-bind: the server's host key and the session id
    var hostKey: Data?
    var session: Data?
    init(peer: Caller) { self.peer = peer }

    /// A keyfob client on this Mac, not a forwarded agent: never through ssh
    var isLocalClient: Bool { !forwarded && peer.chain.first?.name != "ssh" }
  }

  /// Connections are short (ssh connects per authentication); a long-lived one
  /// only holds a slot
  private static let maxConnectionSeconds: TimeInterval = 600

  private func serve(_ fd: Int32) {
    let connection = Connection(peer: Caller(socket: fd))
    let opened = Date()
    while Date().timeIntervalSince(opened) < SSHAgent.maxConnectionSeconds,
      let request = readMessage(fd)
    {
      connection.peer = Caller(socket: fd)
      let response = handle(request, connection: connection)
      var framed = SSHWriter()
      framed.string(response)
      guard writeAll(fd, framed.data) else { return }
    }
  }

  private func handle(_ request: Data, connection: Connection) -> Data {
    var reader = SSHReader(request)
    guard let type = try? reader.byte() else { return failure() }

    switch Message(rawValue: type) {
    case .requestIdentities:
      var writer = SSHWriter()
      writer.byte(Message.identitiesAnswer.rawValue)
      let keys = Key.all(.ssh).compactMap { key in
        (try? key.signingPublicKey()).map { (key.name, SSHKey.blob($0)) }
      }
      writer.uint32(UInt32(keys.count))
      for (name, blob) in keys {
        writer.string(blob)
        writer.string(name)
      }
      return writer.data

    case .extension:
      return handleExtension(&reader, connection: connection)

    case .signRequest:
      guard let keyBlob = try? reader.string(), let data = try? reader.string(),
        let key = Key.all(.ssh).first(where: {
          (try? $0.signingPublicKey()).map(SSHKey.blob) == keyBlob
        }),
        let handle = try? Data(contentsOf: key.handle)
      else { return failure() }
      let peer = connection.peer
      // Also forwarded: anything else reaching us through the local ssh
      // client, which itself only ever signs logins, and only after binding
      let viaSSH = peer.chain.first?.name == "ssh"
      let forwarded =
        connection.forwarded || (viaSSH && (SignRequest.loginUser(data) == nil || !connection.bound))
      let request = SignRequest(
        data: data, caller: peer, key: key, forwarded: forwarded, hostKey: connection.hostKey,
        session: connection.session)
      guard
        let raw = use(
          .sign, handle: handle, protection: key.protection, payload: data,
          action: request.action, operation: request.operation, caller: peer),
        let signature = try? P256.Signing.ECDSASignature(rawRepresentation: raw)
      else { return failure() }
      var writer = SSHWriter()
      writer.byte(Message.signResponse.rawValue)
      writer.string(SSHKey.signature(signature))
      return writer.data

    default:
      return failure()
    }
  }

  private func handleExtension(_ reader: inout SSHReader, connection: Connection) -> Data {
    switch try? reader.text() {
    case "session-bind@openssh.com":
      // string hostkey, string session id, string signature, bool is_forwarding.
      // The host key is the server ssh really reached, whatever argv says.
      guard let hostKey = try? reader.string(), let session = try? reader.string(),
        (try? reader.string()) != nil, let forwarding = try? reader.byte()
      else { return failure() }
      connection.bound = true
      connection.hostKey = hostKey
      connection.session = session
      if forwarding != 0 { connection.forwarded = true }
      return Data([Message.success.rawValue])

    case Extension.agree:
      // age only, and only keyfob's own age keys (never the credentials key);
      // other identities get an empty answer and prompt in their own process
      guard connection.isLocalClient, (try? reader.text()) == "age",
        let handle = try? reader.string(), let share = try? reader.string(),
        (try? reader.text()) != nil
      else { return failure() }
      let credentialsKey = try? Data(contentsOf: Paths.credentialsKey)
      guard handle != credentialsKey, let key = Key.age(matching: handle) else {
        var writer = SSHWriter()
        writer.byte(Message.success.rawValue)
        writer.string(Data())
        return writer.data
      }
      let peer = connection.peer
      guard
        let secret = use(
          .agree, handle: handle, protection: key.protection, payload: share,
          action: Prompt.ageDecrypt(peer, key: key), operation: .ageDecrypt, caller: peer)
      else { return failure() }
      var writer = SSHWriter()
      writer.byte(Message.success.rawValue)
      writer.string(secret)
      return writer.data

    case Extension.credential:
      // The agent opens the credential file itself: the ECDH secret never
      // leaves it, and plaintext comes back only when the file authenticates
      // against this id (the host the approval and the prompt name)
      guard connection.isLocalClient, let id = try? reader.text(),
        let sealed = try? reader.string(),
        let handle = try? Data(contentsOf: Paths.credentialsKey)
      else { return failure() }
      let peer = connection.peer
      let user = GitCredential.storedUsername(sealed) ?? ""
      let action = Prompt.gitCredentials(peer, url: id)
      let operation = Reuse.Operation.gitCredentials(
        host: URLComponents(string: id)?.host ?? id, user: user)
      guard
        let plaintext = try? GitCredential.open(sealed, id: id, agree: { share in
          guard
            let secret = use(
              .agree, handle: handle, protection: SecureEnclaveKeys.credentialsProtection,
              payload: share.x963Representation, action: action, operation: operation,
              caller: peer)
          else { throw KeyfobError("denied") }
          return secret
        })
      else { return failure() }
      var writer = SSHWriter()
      writer.byte(Message.success.rawValue)
      writer.string(plaintext)
      return writer.data

    case Extension.lock:
      // Not for a forwarded agent: a remote host must not clear local approvals
      guard connection.isLocalClient else { return failure() }
      Unlocker.stopAll()
      return Data([Message.success.rawValue])

    case Extension.status:
      // Not for a forwarded agent: approvals name local repos and apps
      guard connection.isLocalClient else { return failure() }
      let active = Unlocker.active
      var writer = SSHWriter()
      writer.byte(Message.success.rawValue)
      writer.string(active.joined(separator: "\n"))
      return writer.data

    default:
      return failure()
    }
  }

  /// One key use: Touch ID unless the policy lets an earlier approval cover
  /// it, audit log either way. Nil when denied.
  private func use(
    _ mode: Persona.Mode, handle: Data, protection: Protection, payload: Data, action: String,
    operation: Reuse.Operation, caller: Caller
  ) -> Data? {
    let grant = Reuse.grant(operation, caller: caller, keyHandle: handle, protection: protection)
    let text = grant.map { action + "\n" + $0.promptLine } ?? action
    let app = caller.displayApp
    keyLock.lock()
    defer { keyLock.unlock() }
    do {
      let (result, reused) = try Persona.unlock(
        mode, handle: handle, protection: protection, payload: payload,
        reason: caller.reason(text, speaker: Persona.fileName(app)), as: app, grant: grant)
      AuditLog.record(action, caller: caller, outcome: reused ? "reused" : "allowed")
      return result
    } catch {
      AuditLog.record(action, caller: caller, outcome: "denied")
      log("refused: \(error.localizedDescription)")
      return nil
    }
  }

  private func failure() -> Data { Data([Message.failure.rawValue]) }

  private static func setTimeout(_ fd: Int32, _ option: Int32, seconds: Int) {
    var timeout = timeval(tv_sec: seconds, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, option, &timeout, socklen_t(MemoryLayout<timeval>.size))
  }

  private func readMessage(_ fd: Int32) -> Data? {
    guard let header = readExactly(fd, 4) else { return nil }
    let length = header.reduce(0) { $0 << 8 | Int($1) }
    guard length > 0, length <= 256 * 1024 else { return nil }
    return readExactly(fd, length)
  }

  private func readExactly(_ fd: Int32, _ count: Int) -> Data? {
    var buffer = [UInt8](repeating: 0, count: count)
    var done = 0
    while done < count {
      let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress! + done, count - done) }
      if n <= 0 { return nil }
      done += n
    }
    return Data(buffer)
  }

  private func writeAll(_ fd: Int32, _ data: Data) -> Bool {
    let bytes = [UInt8](data)
    var done = 0
    while done < bytes.count {
      let n = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + done, bytes.count - done) }
      if n <= 0 { return false }
      done += n
    }
    return true
  }

  private func posixError(_ what: String) -> KeyfobError {
    KeyfobError("\(what): \(String(cString: strerror(errno)))")
  }

  private func log(_ message: String) {
    FileHandle.standardError.write(Data("keyfob: \(message)\n".utf8))
  }
}

extension Caller {
  /// The process on the other end of the agent socket and its ancestors
  /// (ssh's parent is usually git, which is what the user cares about).
  init(socket fd: Int32) {
    var pid: pid_t = 0
    var length = socklen_t(MemoryLayout<pid_t>.size)
    getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &length)
    self.init(pid: pid)
  }
}

/// An SSH signature request: the action shown on the Touch ID sheet, and
/// what kind of operation it is for the reuse policy.
struct SignRequest {
  let action: String
  let operation: Reuse.Operation

  /// Username of an SSH_MSG_USERAUTH_REQUEST publickey signature, nil for
  /// anything else (SSHSIG file/commit signatures, …).
  static func loginUser(_ data: Data) -> String? {
    var reader = SSHReader(data)
    guard (try? reader.string()) != nil, (try? reader.byte()) == 50 else { return nil }
    return try? reader.text()
  }

  /// `forwarded`: the request comes from another machine through `ssh -A`.
  /// The local process chain says nothing about it, so the sheet shows only
  /// what is asked and where it came from, and it never reuses an approval.
  /// `hostKey`/`session` come from ssh's session-bind: an SSH login reuses an
  /// approval only for the server that really answered (its host key), and
  /// only when the signed login belongs to that bound session.
  init(data: Data, caller: Caller, key: Key, forwarded: Bool, hostKey: Data?, session: Data?) {
    let namespace: String? =
      data.starts(with: Data("SSHSIG".utf8))
      ? { var reader = SSHReader(data.dropFirst(6)); return (try? reader.text()) ?? "" }() : nil
    let user = SignRequest.loginUser(data)

    if forwarded {
      let what =
        namespace == "git" ? "sign a Git commit or tag"
        : namespace.map { "sign data for \($0)" }
        ?? user.map { "log in over SSH as \($0)" } ?? "sign SSH data"
      action = Prompt.forwarded(caller, action: what, key: key)
      operation = .always
      return
    }
    if let namespace {
      guard namespace == "git" else {
        action = Prompt.lines("sign data for \(namespace)", [], key: key.promptLine)
        operation = .always
        return
      }
      // Reused only for a commit whose content was checked against the hash
      // being signed; tags, other objects and anything unverified always ask
      let object = caller.signedObject(data)
      action = Prompt.gitSigning(caller, object: object, key: key)
      operation = .gitSign(verifiedCommit: object?.kind == .commit)
      return
    }
    if let user {
      action = Prompt.sshLogin(caller, user: user, key: key)
      var loginSession = SSHReader(data)
      let signedSession = try? loginSession.string()
      // Pushes (git-receive-pack, whatever alias or config started them) ask
      let push = caller.sshRemoteService == "git-receive-pack"
      if !push, let hostKey, let session, signedSession == session {
        let fingerprint = Data(SHA256.hash(data: hostKey)).base64EncodedString()
        operation = .sshLogin(target: "\(user)@SHA256:\(fingerprint)")
      } else {
        operation = .sshLogin(target: nil)
      }
      return
    }
    action = Prompt.lines("sign SSH data", [("🔧", caller.initiatorLabel)], key: key.promptLine)
    operation = .always
  }
}

/// Client side of the keyfob agent extensions, used by `keyfob lock` and
/// `status`, the git credential helper and the age plugin.
enum AgentClient {
  enum Answer {
    case result(Data)
    case denied
    /// No agent listening: the caller does the work itself
    case unavailable
  }

  static var socketPath: String {
    ProcessInfo.processInfo.environment["KEYFOB_AGENT_SOCKET"].flatMap { $0.isEmpty ? nil : $0 }
      ?? Paths.agentSocket.path
  }

  static var isAvailable: Bool {
    let fd = connect()
    if fd >= 0 { close(fd) }
    return fd >= 0
  }

  /// ECDH with a Secure Enclave key, Touch ID and reuse decided by the agent.
  static func agree(purpose: String, handle: Data, share: Data, context: String) -> Answer {
    var writer = SSHWriter()
    writer.byte(SSHAgent.Message.extension.rawValue)
    writer.string(SSHAgent.Extension.agree)
    writer.string(purpose)
    writer.string(handle)
    writer.string(share)
    writer.string(context)
    guard let response = send(writer.data) else { return .unavailable }
    var reader = SSHReader(response)
    guard (try? reader.byte()) == SSHAgent.Message.success.rawValue,
      let secret = try? reader.string()
    else { return .denied }
    // Empty: not one of keyfob's keys, use it in this process
    return secret.isEmpty ? .unavailable : .result(secret)
  }

  /// Decrypted, verified git credential file contents.
  static func credential(id: String, sealed: Data) -> Answer {
    var writer = SSHWriter()
    writer.byte(SSHAgent.Message.extension.rawValue)
    writer.string(SSHAgent.Extension.credential)
    writer.string(id)
    writer.string(sealed)
    guard let response = send(writer.data) else { return .unavailable }
    var reader = SSHReader(response)
    guard (try? reader.byte()) == SSHAgent.Message.success.rawValue,
      let plaintext = try? reader.string()
    else { return .denied }
    return .result(plaintext)
  }

  static func lock() -> Bool {
    var writer = SSHWriter()
    writer.byte(SSHAgent.Message.extension.rawValue)
    writer.string(SSHAgent.Extension.lock)
    return send(writer.data)?.first == SSHAgent.Message.success.rawValue
  }

  static func status() -> [String]? {
    var writer = SSHWriter()
    writer.byte(SSHAgent.Message.extension.rawValue)
    writer.string(SSHAgent.Extension.status)
    guard let response = send(writer.data) else { return nil }
    var reader = SSHReader(response)
    guard (try? reader.byte()) == SSHAgent.Message.success.rawValue,
      let text = try? reader.text()
    else { return nil }
    return text.isEmpty ? [] : text.components(separatedBy: "\n")
  }

  private static func connect() -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { return -1 }
    var address = sockaddr_un()
    address.sun_family = sa_family_t(AF_UNIX)
    let pathBytes = Array(socketPath.utf8)
    guard pathBytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
      close(fd)
      return -1
    }
    withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: pathBytes) }
    let connected = withUnsafePointer(to: &address) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
        Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
      }
    }
    guard connected == 0 else {
      close(fd)
      return -1
    }
    return fd
  }

  /// One request and its response; nil when no agent answers.
  private static func send(_ message: Data) -> Data? {
    let fd = connect()
    guard fd >= 0 else { return nil }
    defer { close(fd) }
    var framed = SSHWriter()
    framed.string(message)
    let bytes = [UInt8](framed.data)
    var done = 0
    while done < bytes.count {
      let n = bytes.withUnsafeBytes { write(fd, $0.baseAddress! + done, bytes.count - done) }
      if n <= 0 { return nil }
      done += n
    }
    func readExactly(_ count: Int) -> Data? {
      var buffer = [UInt8](repeating: 0, count: count)
      var got = 0
      while got < count {
        let n = buffer.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, count - got) }
        if n <= 0 { return nil }
        got += n
      }
      return Data(buffer)
    }
    // No read timeout: the agent may be waiting for the user's finger
    guard let header = readExactly(4) else { return nil }
    let length = header.reduce(0) { $0 << 8 | Int($1) }
    guard length > 0, length <= 1 << 20 else { return nil }
    return readExactly(length)
  }
}
