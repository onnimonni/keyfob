import CryptoKit
import Darwin
import Foundation

/// Minimal ssh-agent (draft-miller-ssh-agent): lists the keyfob key and signs
/// with it. Every signature needs Touch ID. Everything else is refused.
final class SSHAgent {
  private enum Message: UInt8 {
    case failure = 5
    case requestIdentities = 11
    case identitiesAnswer = 12
    case signRequest = 13
    case signResponse = 14
  }

  private let socketPath: String
  /// One Touch ID sheet at a time
  private let signLock = NSLock()

  init(socketPath: String) {
    self.socketPath = socketPath
  }

  func run() throws -> Never {
    signal(SIGPIPE, SIG_IGN)
    try Paths.ensureDirectory(URL(fileURLWithPath: socketPath).deletingLastPathComponent())
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
      if client < 0 { continue }
      Thread.detachNewThread { [self] in
        serve(client)
        close(client)
      }
    }
  }

  private func serve(_ fd: Int32) {
    let peer = Caller(socket: fd)
    while let request = readMessage(fd) {
      let response = handle(request, peer: peer)
      var framed = SSHWriter()
      framed.string(response)
      guard writeAll(fd, framed.data) else { return }
    }
  }

  private func handle(_ request: Data, peer: Caller) -> Data {
    var reader = SSHReader(request)
    guard let type = try? reader.byte() else { return failure() }

    switch Message(rawValue: type) {
    case .requestIdentities:
      var writer = SSHWriter()
      writer.byte(Message.identitiesAnswer.rawValue)
      if let key = try? publicKey() {
        writer.uint32(1)
        writer.string(SSHKey.blob(key))
        writer.string("keyfob")
      } else {
        writer.uint32(0)
      }
      return writer.data

    case .signRequest:
      do {
        let keyBlob = try reader.string()
        let data = try reader.string()
        guard let key = try? publicKey(), keyBlob == SSHKey.blob(key) else { return failure() }

        let action = SignReason.describe(data, caller: peer)
        signLock.lock()
        defer { signLock.unlock() }
        do {
          let signature =
            if let app = peer.app {
              try Persona.sign(
                data, reason: peer.reason(action, speaker: Persona.fileName(app)), as: app)
            } else {
              try SecureEnclaveKeys.loadSigningKey(reason: peer.reason(action))
                .signature(for: data)
            }
          AuditLog.record(action, caller: peer, outcome: "allowed")

          var writer = SSHWriter()
          writer.byte(Message.signResponse.rawValue)
          writer.string(SSHKey.signature(signature))
          return writer.data
        } catch {
          AuditLog.record(action, caller: peer, outcome: "denied")
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

  private func publicKey() throws -> P256.Signing.PublicKey {
    // Reading the public key never prompts
    try SecureEnclave.P256.Signing.PrivateKey(
      dataRepresentation: Data(contentsOf: Paths.sshKey)
    ).publicKey
  }

  private func failure() -> Data { Data([Message.failure.rawValue]) }

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

/// Turns the bytes being signed into the action shown on the Touch ID sheet.
enum SignReason {
  static func describe(_ data: Data, caller: Caller) -> String {
    if data.starts(with: Data("SSHSIG".utf8)) {
      var reader = SSHReader(data.dropFirst(6))
      let namespace = (try? reader.text()) ?? ""
      guard namespace == "git" else { return "sign data for \(namespace)" }
      var action = caller.gitSubcommand == "tag" ? "sign a Git tag" : "sign a Git commit"
      if let subject = caller.signedSubject { action += ":\n'\(subject)'" }
      if let repository = caller.repository { action += "\nin:\n'\(repository)'" }
      return action
    }

    // SSH_MSG_USERAUTH_REQUEST publickey signature
    var reader = SSHReader(data)
    if (try? reader.string()) != nil, (try? reader.byte()) == 50,
      let user = try? reader.text()
    {
      guard let target = caller.sshTarget(user: user) else { return "log in over SSH as \(user)" }
      var action = "log in over SSH to:\n'\(target)'"
      if let repository = caller.sshRemoteRepository { action += "\nfor:\n'\(repository)'" }
      return action
    }
    return "sign SSH data"
  }
}
