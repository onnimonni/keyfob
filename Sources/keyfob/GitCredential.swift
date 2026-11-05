import CryptoKit
import Foundation

/// git credential helper (gitcredentials(7)). Tokens are encrypted to a
/// Secure Enclave key: storing needs only its public key, reading needs Touch ID.
enum GitCredential {
  /// v2 keeps the username readable (authenticated, not secret), so lookups
  /// and erases for another user need no Touch ID. v1 files still open.
  private static let magic = Data("KFC2".utf8)
  private static let legacyMagic = Data("KFC1".utf8)
  private static let info = Data("keyfob git-credential v1".utf8)
  private static let shareLength = 65
  /// Fields worth keeping between `store` and `get`
  private static let storedFields = [
    "username", "password", "password_expiry_utc", "oauth_refresh_token",
  ]

  static func run(_ operation: String) throws {
    let request = parse(FileHandle.standardInput.readDataToEndOfFile())
    guard let proto = request["protocol"], let host = request["host"] else { return }
    var id = "\(proto)://\(host)"
    if let path = request["path"], !path.isEmpty { id += "/\(path)" }
    let file = Paths.credentials.appendingPathComponent(fileName(id))
    let sealed = try? Data(contentsOf: file)
    // A credential stored for someone else is left alone
    if let wanted = request["username"], let stored = sealed.flatMap(storedUsername),
      wanted != stored
    {
      return
    }

    switch operation {
    case "get":
      guard let sealed else { return }
      let caller = Caller.parent
      let action = Prompt.gitCredentials(caller, url: id)
      let plaintext: Data
      do {
        plaintext = try open(sealed, id: id, reason: caller.reason(action))
        AuditLog.record(action, caller: caller, outcome: "allowed")
      } catch {
        AuditLog.record(action, caller: caller, outcome: "denied")
        throw error
      }
      let stored = parse(plaintext)
      if let wanted = request["username"], wanted != stored["username"] { return }
      if let expiry = stored["password_expiry_utc"].flatMap(TimeInterval.init),
        expiry < Date().timeIntervalSince1970
      {
        return
      }
      print(format(stored), terminator: "")

    case "store":
      guard request["password"] != nil else { return }
      let fields = request.filter { storedFields.contains($0.key) }
      try Paths.writePrivate(
        try seal(Data(format(fields).utf8), id: id, username: fields["username"] ?? ""), to: file)

    case "erase":
      try? FileManager.default.removeItem(at: file)

    default:
      // gitcredentials(7): ignore unknown operations
      return
    }
  }

  /// `KFC2`, username length (UInt16) and bytes, ephemeral P-256 share,
  /// ChaChaPoly box authenticating the id and the username.
  private static func seal(_ plaintext: Data, id: String, username: String) throws -> Data {
    guard Paths.exists(Paths.credentialsKey) else {
      throw KeyfobError("no credentials key, run `keyfob init` first")
    }
    let recipient = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: Data(contentsOf: Paths.credentialsKey)
    ).publicKey
    let ephemeral = P256.KeyAgreement.PrivateKey()
    let key = try ephemeral.sharedSecretFromKeyAgreement(with: recipient)
      .hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeral.publicKey.x963Representation + recipient.x963Representation,
        sharedInfo: info, outputByteCount: 32)
    let user = Data(username.utf8.prefix(Int(UInt16.max)))
    let box = try ChaChaPoly.seal(
      plaintext, using: key, authenticating: authenticated(id: id, username: user))
    return magic + Data([UInt8(user.count >> 8), UInt8(user.count & 0xFF)]) + user
      + ephemeral.publicKey.x963Representation + box.combined
  }

  private static func open(_ sealed: Data, id: String, reason: String) throws -> Data {
    let body: Data
    let aad: Data
    if let user = storedUsernameData(sealed) {
      body = Data(sealed.dropFirst(magic.count + 2 + user.count))
      aad = authenticated(id: id, username: user)
    } else if sealed.starts(with: legacyMagic) {
      body = Data(sealed.dropFirst(legacyMagic.count))
      aad = Data(id.utf8)
    } else {
      throw KeyfobError("unrecognized credential file for \(id)")
    }
    guard body.count > shareLength else { throw KeyfobError("truncated credential file for \(id)") }
    let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: body.prefix(shareLength))
    let privateKey = try SecureEnclaveKeys.loadAgreementKey(reason: reason)
    let key = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
      .hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeral.x963Representation + privateKey.publicKey.x963Representation,
        sharedInfo: info, outputByteCount: 32)
    let box = try ChaChaPoly.SealedBox(combined: body.dropFirst(shareLength))
    return try ChaChaPoly.open(box, using: key, authenticating: aad)
  }

  private static func authenticated(id: String, username: Data) -> Data {
    Data(id.utf8) + Data([0]) + username
  }

  /// Username bytes of a v2 file; nil for v1 or broken files.
  private static func storedUsernameData(_ sealed: Data) -> Data? {
    guard sealed.starts(with: magic), sealed.count >= magic.count + 2 else { return nil }
    let bytes = [UInt8](sealed)
    let length = Int(bytes[magic.count]) << 8 | Int(bytes[magic.count + 1])
    let start = magic.count + 2
    guard bytes.count >= start + length else { return nil }
    return Data(bytes[start..<start + length])
  }

  /// Username of a v2 file without decrypting it; nil for v1 files.
  private static func storedUsername(_ sealed: Data) -> String? {
    storedUsernameData(sealed).map { String(decoding: $0, as: UTF8.self) }
  }

  private static func parse(_ data: Data) -> [String: String] {
    var fields: [String: String] = [:]
    for line in String(decoding: data, as: UTF8.self).split(whereSeparator: \.isNewline) {
      guard let separator = line.firstIndex(of: "=") else { continue }
      fields[String(line[..<separator])] = String(line[line.index(after: separator)...])
    }
    return fields
  }

  private static func format(_ fields: [String: String]) -> String {
    storedFields.compactMap { key in fields[key].map { "\(key)=\($0)\n" } }.joined()
  }

  private static func fileName(_ id: String) -> String {
    var allowed = CharacterSet.alphanumerics
    allowed.insert(charactersIn: "-._")
    return id.addingPercentEncoding(withAllowedCharacters: allowed)! + ".cred"
  }
}
