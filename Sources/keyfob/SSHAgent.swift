import CryptoKit
import Darwin
import Foundation

/// Minimal ssh-agent (draft-miller-ssh-agent): lists the keyfob key and signs
/// with it. Every signature needs Touch ID. Everything else is refused.
final class SSHAgent {
  private enum Message: UInt8 {
    case failure = 5
    case success = 6
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
    case `extension` = 27
  }

  /// Idle or slow clients each hold a thread; cap them.
  private static let maxConnections = 64
  private let connectionLock = NSLock()
  private var connections = 0

  private let socketPath: String
  /// One Touch ID sheet at a time
  private let signLock = NSLock()

  init(socketPath: String) {
    self.socketPath = socketPath
  }

  func run() throws -> Never {
    signal(SIGPIPE, SIG_IGN)
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
    guard listen(server, 16) == 0 else { throw posixError("listen") }

    log("listening on \(socketPath)")
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
    let peer: Caller
    var bound = false
    var forwarded = false
    init(peer: Caller) { self.peer = peer }
  }

  private func serve(_ fd: Int32) {
    let connection = Connection(peer: Caller(socket: fd))
    while let request = readMessage(fd) {
      let response = handle(request, connection: connection)
      var framed = SSHWriter()
      framed.string(response)
      guard writeAll(fd, framed.data) else { return }
    }
  }

  private func handle(_ request: Data, connection: Connection) -> Data {
    var reader = SSHReader(request)
    guard let type = try? reader.byte() else { return failure() }
    let peer = connection.peer

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
      // string "session-bind@openssh.com", string hostkey, string session id,
      // string signature, bool is_forwarding
      guard (try? reader.text()) == "session-bind@openssh.com",
        (try? reader.string()) != nil, (try? reader.string()) != nil,
        (try? reader.string()) != nil, let forwarding = try? reader.byte()
      else { return failure() }
      connection.bound = true
      if forwarding != 0 { connection.forwarded = true }
      return Data([Message.success.rawValue])

    case .signRequest:
      do {
        let keyBlob = try reader.string()
        let data = try reader.string()
        guard
          let key = Key.all(.ssh).first(where: {
            (try? $0.signingPublicKey()).map(SSHKey.blob) == keyBlob
          })
        else { return failure() }

        // Also forwarded: anything else reaching us through the local ssh
        // client, which itself only ever signs logins, and only after binding
        let viaSSH = peer.chain.first?.name == "ssh"
        let forwarded =
          connection.forwarded || (viaSSH && (SignRequest.loginUser(data) == nil || !connection.bound))
        let request = SignRequest(data: data, caller: peer, key: key, forwarded: forwarded)
        signLock.lock()
        defer { signLock.unlock() }
        do {
          let app = peer.displayApp
          let (signature, reused) = try Persona.sign(
            data, with: key, reason: peer.reason(request.action, speaker: Persona.fileName(app)),
            as: app, reuseScope: request.reuseScope)
          AuditLog.record(request.action, caller: peer, outcome: reused ? "reused" : "allowed")

          var writer = SSHWriter()
          writer.byte(Message.signResponse.rawValue)
          writer.string(SSHKey.signature(signature))
          return writer.data
        } catch {
          AuditLog.record(request.action, caller: peer, outcome: "denied")
          throw error
        }
      } catch {
        log("sign refused: \(error.localizedDescription)")
        return failure()
      }

    default:
      return failure()
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

/// A signature request: the action shown on the Touch ID sheet, and how far
/// an approval of it may be reused.
struct SignRequest {
  let action: String
  /// Requests sharing a scope reuse one approval of a normal key for a few
  /// minutes; nil means always ask. A scope is one app process, one key and
  /// one kind of action (signing in a repository, logging in to a host).
  let reuseScope: String?

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
  init(data: Data, caller: Caller, key: Key, forwarded: Bool) {
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
      reuseScope = nil
      return
    }

    let instance = caller.appInstance.map { "\($0)\u{0}\(key.fingerprint)" }
    if let namespace {
      guard namespace == "git" else {
        action = Prompt.lines("sign data for \(namespace)", [], key: key.promptLine)
        reuseScope = nil
        return
      }
      let tag = caller.gitSubcommand == "tag"
      action = Prompt.gitSigning(caller, tag: tag, key: key)
      // Tags mark releases: always ask
      reuseScope = tag ? nil : instance.map { "\($0)\u{0}sign\u{0}\(caller.repositoryPath ?? "")" }
      return
    }

    if let user {
      action = Prompt.sshLogin(caller, user: user, key: key)
      // Destructive pushes deserve their own look: always ask
      let destructive = caller.push.map { $0.force || $0.delete } ?? false
      let host = caller.sshEndpoint.map { "\(user)@\($0.host):\($0.port)" }
      reuseScope =
        destructive ? nil : instance.flatMap { i in host.map { "\(i)\u{0}login\u{0}\($0)" } }
      return
    }
    action = Prompt.lines("sign SSH data", [("🔧", caller.initiatorLabel)], key: key.promptLine)
    reuseScope = nil
  }
}
