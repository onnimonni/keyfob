import CryptoKit
import Foundation
import LocalAuthentication

struct KeyfobError: LocalizedError {
  let errorDescription: String?
  init(_ message: String) { errorDescription = message }
}

/// Where keyfob keeps its key handles. The files only hold Secure Enclave
/// wrapped blobs: they are useless on any other Mac.
enum Paths {
  static var home: URL {
    let env = ProcessInfo.processInfo.environment
    if let dir = env["KEYFOB_HOME"], !dir.isEmpty {
      return URL(fileURLWithPath: dir)
    }
    let config = env["XDG_CONFIG_HOME"].flatMap { $0.isEmpty ? nil : $0 }
      ?? NSHomeDirectory() + "/.config"
    return URL(fileURLWithPath: config).appendingPathComponent("keyfob")
  }
  static var credentialsKey: URL { home.appendingPathComponent("credentials.key") }
  static var credentials: URL { home.appendingPathComponent("credentials") }
  static var agentSocket: URL { home.appendingPathComponent("agent.sock") }
  static var gitConfig: URL { home.appendingPathComponent("gitconfig") }
  static var sshConfig: URL { home.appendingPathComponent("ssh_config") }
  static var allowedSigners: URL { home.appendingPathComponent("allowed_signers") }

  /// Creates `url` if needed and makes it private, also when something else
  /// (e.g. home-manager) created it first.
  static func ensureDirectory(_ url: URL) throws {
    try FileManager.default.createDirectory(
      at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
  }

  /// Atomic write of a 0600 file that is never readable by others, not even
  /// briefly: the temporary file is created with those permissions.
  static func writePrivate(_ data: Data, to url: URL) throws {
    try ensureDirectory(url.deletingLastPathComponent())
    let temporary = url.path + ".\(getpid()).tmp"
    unlink(temporary)
    let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL, 0o600)
    guard fd >= 0 else { throw KeyfobError("cannot write \(url.path)") }
    let written = data.withUnsafeBytes { write(fd, $0.baseAddress, data.count) }
    close(fd)
    guard written == data.count, rename(temporary, url.path) == 0 else {
      unlink(temporary)
      throw KeyfobError("cannot write \(url.path)")
    }
  }

  static func exists(_ url: URL) -> Bool {
    FileManager.default.fileExists(atPath: url.path)
  }
}

/// How a Secure Enclave key is protected.
enum Protection: String, Codable {
  /// Touch ID or the login password; the SSH agent reuses one approval for
  /// a few minutes per app and key.
  case normal
  /// Touch ID only, every use; enrolling or removing a finger destroys it.
  case dangerous
  /// Touch ID only, survives enrolling fingers (git credentials key).
  case touchID
  /// No user presence: only for the test suite.
  case none

  var ageAccessControl: KeyAccessControl {
    switch self {
    case .normal: .anyBiometryOrPasscode
    case .dangerous: .currentBiometry
    case .touchID: .anyBiometry
    case .none: .none
    }
  }

  func accessControl() throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    switch self {
    case .normal: flags.insert(.userPresence)
    case .dangerous: flags.insert(.biometryCurrentSet)
    case .touchID: flags.insert(.biometryAny)
    case .none: break
    }
    var error: Unmanaged<CFError>?
    guard
      let access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error)
    else {
      throw error!.takeRetainedValue() as Error
    }
    return access
  }
}

/// A named SSH or age key: `ssh/<name>.key` + `.pub`, or `age/<name>.txt`,
/// each with a `<name>.json` recording its protection.
struct Key {
  enum Kind: String, CaseIterable {
    case ssh, age

    var directory: URL { Paths.home.appendingPathComponent(rawValue) }
    var label: String { self == .ssh ? "SSH" : "age" }
    var handleExtension: String { self == .ssh ? "key" : "txt" }
  }

  private struct Metadata: Codable {
    var protection: Protection
  }

  static let defaultName = "default"

  let kind: Kind
  let name: String
  let protection: Protection

  var handle: URL { kind.directory.appendingPathComponent("\(name).\(kind.handleExtension)") }
  var publicKeyFile: URL { kind.directory.appendingPathComponent("\(name).pub") }
  private var metadataFile: URL { kind.directory.appendingPathComponent("\(name).json") }
  var isDangerous: Bool { protection == .dangerous }

  /// Last line of the Touch ID sheet; nothing for the everyday `default` key.
  var promptLine: String? {
    if isDangerous { return "🚨 using dangerous '\(name)' key" }
    return name == Key.defaultName ? nil : "🔑 using '\(name)' key"
  }

  static func all(_ kind: Kind) -> [Key] {
    let files = (try? FileManager.default.contentsOfDirectory(atPath: kind.directory.path)) ?? []
    return files.filter { $0.hasSuffix(".\(kind.handleExtension)") }.sorted().compactMap {
      named(kind, String($0.dropLast(kind.handleExtension.count + 1)))
    }
  }

  static func named(_ kind: Kind, _ name: String) -> Key? {
    let probe = Key(kind: kind, name: name, protection: .normal)
    guard Paths.exists(probe.handle) else { return nil }
    let metadata = (try? Data(contentsOf: probe.metadataFile))
      .flatMap { try? JSONDecoder().decode(Metadata.self, from: $0) }
    // Fail closed: a key whose metadata is missing or broken is treated as dangerous
    return Key(kind: kind, name: name, protection: metadata?.protection ?? .dangerous)
  }

  /// Identifies the key material, so a deleted and recreated key of the same
  /// name never shares an approval with the old one.
  var fingerprint: String {
    let data = (try? Data(contentsOf: handle)) ?? Data()
    return SHA256.hash(data: data).prefix(8).map { String(format: "%02x", $0) }.joined()
  }

  static func create(_ kind: Kind, _ name: String, protection: Protection) throws -> Key {
    guard !name.isEmpty, name.allSatisfy({ $0.isLetter || $0.isNumber || "-_.".contains($0) }),
      !name.hasPrefix(".")
    else {
      throw KeyfobError("key names may only use letters, digits, '-', '_' and '.'")
    }
    guard named(kind, name) == nil else {
      throw KeyfobError("\(kind.label) key '\(name)' already exists")
    }
    try SecureEnclaveKeys.requireSecureEnclave()
    let key = Key(kind: kind, name: name, protection: protection)
    switch kind {
    case .ssh:
      let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
        accessControl: protection.accessControl())
      try Paths.writePrivate(privateKey.dataRepresentation, to: key.handle)
      try Paths.writePrivate(Data((key.authorizedKey(privateKey.publicKey) + "\n").utf8),
        to: key.publicKeyFile)
    case .age:
      let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
      let (contents, _) = try plugin.generateKey(
        accessControl: protection.ageAccessControl, recipientType: .se, now: Date())
      try Paths.writePrivate(Data(contents.utf8), to: key.handle)
    }
    try Paths.writePrivate(
      try JSONEncoder().encode(Metadata(protection: protection)), to: key.metadataFile)
    return key
  }

  func delete() throws {
    for file in [handle, publicKeyFile, metadataFile] where Paths.exists(file) {
      try FileManager.default.removeItem(at: file)
    }
  }

  /// `ecdsa-sha2-nistp256 AAAA… prod@Onnis-Mac` or `age1se1…`; never prompts.
  func publicKey() throws -> String {
    switch kind {
    case .ssh:
      return authorizedKey(try signingPublicKey())
    case .age:
      let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
      return try plugin.generateRecipients(
        input: String(contentsOf: handle, encoding: .utf8), recipientType: .se)
    }
  }

  func signingPublicKey() throws -> P256.Signing.PublicKey {
    try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: Data(contentsOf: handle))
      .publicKey
  }

  func loadSigningKey(context: LAContext) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(
      dataRepresentation: Data(contentsOf: handle), authenticationContext: context)
  }

  private func authorizedKey(_ publicKey: P256.Signing.PublicKey) -> String {
    SSHKey.authorizedKey(publicKey, comment: "\(name)@\(Setup.hostName)")
  }

  /// The age key whose identity wraps this P-256 key handle.
  static func age(matching p256Data: Data) -> Key? {
    all(.age).first { key in
      guard let text = try? String(contentsOf: key.handle, encoding: .utf8),
        let line = text.split(whereSeparator: \.isNewline).first(where: {
          $0.hasPrefix("AGE-PLUGIN-SE-")
        }),
        let decoded = try? Bech32().decode(String(line))
      else { return false }
      return decoded.data.range(of: p256Data) != nil
    }
  }
}

enum SecureEnclaveKeys {
  static func requireSecureEnclave() throws {
    guard SecureEnclave.isAvailable else {
      throw KeyfobError("Secure Enclave is not available on this Mac")
    }
  }

  /// A fresh context per operation, so every use asks for Touch ID and names why.
  static func context(reason: String) -> LAContext {
    let context = LAContext()
    context.localizedReason = reason
    context.localizedCancelTitle = "Deny"
    return context
  }

  static func createCredentialsKey(protection: Protection) throws {
    let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(
      accessControl: protection.accessControl())
    try Paths.writePrivate(key.dataRepresentation, to: Paths.credentialsKey)
  }

  static func loadAgreementKey(reason: String) throws
    -> SecureEnclave.P256.KeyAgreement.PrivateKey
  {
    try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: Data(contentsOf: Paths.credentialsKey),
      authenticationContext: context(reason: reason))
  }
}
