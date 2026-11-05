import CryptoKit
import Foundation

/// git credential helper (gitcredentials(7)). Tokens are encrypted to a
/// Secure Enclave key: storing needs only its public key, reading needs Touch ID.
enum GitCredential {
  private static let magic = Data("KFC1".utf8)
  private static let info = Data("keyfob git-credential v1".utf8)
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

    switch operation {
    case "get":
      guard Paths.exists(file) else { return }
      let caller = Caller.parent
      let action = "unlock Git credentials for:\n'\(id)'"
      let plaintext: Data
      do {
        plaintext = try open(Data(contentsOf: file), id: id, reason: caller.reason(action))
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
      let plaintext = format(request.filter { storedFields.contains($0.key) })
      try Paths.writePrivate(try seal(Data(plaintext.utf8), id: id), to: file)

    case "erase":
      try? FileManager.default.removeItem(at: file)

    default:
      // gitcredentials(7): ignore unknown operations
      return
    }
  }

  private static func seal(_ plaintext: Data, id: String) throws -> Data {
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
    let box = try ChaChaPoly.seal(plaintext, using: key, authenticating: Data(id.utf8))
    return magic + ephemeral.publicKey.x963Representation + box.combined
  }

  private static func open(_ sealed: Data, id: String, reason: String) throws -> Data {
    let shareLength = 65
    guard sealed.starts(with: magic), sealed.count > magic.count + shareLength else {
      throw KeyfobError("unrecognized credential file for \(id)")
    }
    let body = sealed.dropFirst(magic.count)
    let ephemeral = try P256.KeyAgreement.PublicKey(x963Representation: body.prefix(shareLength))
    let privateKey = try SecureEnclaveKeys.loadAgreementKey(reason: reason)
    let key = try privateKey.sharedSecretFromKeyAgreement(with: ephemeral)
      .hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: ephemeral.x963Representation + privateKey.publicKey.x963Representation,
        sharedInfo: info, outputByteCount: 32)
    let box = try ChaChaPoly.SealedBox(combined: body.dropFirst(shareLength))
    return try ChaChaPoly.open(box, using: key, authenticating: Data(id.utf8))
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
