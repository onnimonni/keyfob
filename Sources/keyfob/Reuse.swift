import CryptoKit
import Foundation

/// When one Touch ID approval may cover later requests, and which ones.
///
/// An approval is reused only within a scope: the same app process, the same
/// session in it (agent session or terminal tab), the same code identity,
/// the same key and the same kind of request. Anything that widens what an
/// approval does always asks again.
enum Reuse {
  enum Operation {
    /// Signing commits; tags always ask
    case gitSign(tag: Bool)
    /// `user@host:port`; nil when forwarded or unknown (always asks)
    case sshLogin(target: String?)
    /// HTTPS credentials for a host and user
    case gitCredentials(host: String, user: String)
    case ageDecrypt
    /// Never reused
    case always
  }

  struct Grant {
    /// Requests with the same scope share the approval
    let scope: String
    let seconds: TimeInterval
    /// For `keyfob status`: `claude: commits in ~/Projects/x`
    let summary: String

    /// Last line of the Touch ID sheet, so the user knows what they approve
    var promptLine: String { "⏱️ remembered for \(Int(seconds / 60)) min" }
  }

  static let seconds: TimeInterval = 300
  static let ageSeconds: TimeInterval = 120

  /// Identifies key material: a recreated key never inherits an approval.
  static func fingerprint(_ handle: Data) -> String {
    SHA256.hash(data: handle).prefix(8).map { String(format: "%02x", $0) }.joined()
  }

  static func grant(
    _ operation: Operation, caller: Caller, keyHandle: Data, protection: Protection
  ) -> Grant? {
    // Dangerous keys and callers we cannot pin down always ask
    guard protection != .dangerous, let app = caller.appInstance,
      let session = caller.sessionInstance, let identity = caller.codeIdentity
    else { return nil }
    let destructive = caller.push.map { $0.force || $0.delete } ?? false

    let what: String
    let summary: String
    var seconds = Reuse.seconds
    switch operation {
    case .gitSign(let tag):
      guard !tag, let repository = caller.repositoryPath else { return nil }
      what = "sign\u{0}\(repository)"
      summary = "commits in \(Caller.displayPath(repository))"
    case .sshLogin(let target):
      guard let target, !destructive else { return nil }
      what = "login\u{0}\(target)"
      summary = "SSH logins to \(target)"
    case .gitCredentials(let host, let user):
      guard !destructive else { return nil }
      what = "https\u{0}\(host)\u{0}\(user)"
      summary = "Git credentials for \(host)"
    case .ageDecrypt:
      let directory = caller.initiatorDirectory ?? ""
      what = "age\u{0}\(directory)"
      summary = "age decryption in \(directory)"
      seconds = ageSeconds
    case .always:
      return nil
    }
    return Grant(
      scope: [app, session, identity, fingerprint(keyHandle), what].joined(separator: "\u{0}"),
      seconds: seconds, summary: "\(caller.displayApp): \(summary)")
  }
}
