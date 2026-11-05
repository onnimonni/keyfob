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
  static var sshKey: URL { home.appendingPathComponent("ssh.key") }
  static var sshPublicKey: URL { home.appendingPathComponent("ssh.pub") }
  static var ageIdentity: URL { home.appendingPathComponent("age.txt") }
  static var credentialsKey: URL { home.appendingPathComponent("credentials.key") }
  static var credentials: URL { home.appendingPathComponent("credentials") }
  static var agentSocket: URL { home.appendingPathComponent("agent.sock") }
  static var gitConfig: URL { home.appendingPathComponent("gitconfig") }
  static var sshConfig: URL { home.appendingPathComponent("ssh_config") }
  static var allowedSigners: URL { home.appendingPathComponent("allowed_signers") }

  static func ensureDirectory(_ url: URL) throws {
    try FileManager.default.createDirectory(
      at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
  }

  static func writePrivate(_ data: Data, to url: URL) throws {
    try ensureDirectory(url.deletingLastPathComponent())
    try data.write(to: url, options: [.atomic])
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
  }

  static func exists(_ url: URL) -> Bool {
    FileManager.default.fileExists(atPath: url.path)
  }
}

/// How Secure Enclave keys are protected. `touchID` is the only real mode;
/// `none` exists so the test suite can run without a finger on the sensor.
enum Protection {
  case touchID
  case none

  var ageAccessControl: KeyAccessControl {
    self == .touchID ? .anyBiometry : .none
  }

  func accessControl() throws -> SecAccessControl {
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if self == .touchID {
      // biometryAny survives enrolling new fingers, unlike biometryCurrentSet
      flags.insert(.biometryAny)
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

  static func createSigningKey(protection: Protection) throws
    -> SecureEnclave.P256.Signing.PrivateKey
  {
    try SecureEnclave.P256.Signing.PrivateKey(accessControl: protection.accessControl())
  }

  static func loadSigningKey(reason: String) throws -> SecureEnclave.P256.Signing.PrivateKey {
    try SecureEnclave.P256.Signing.PrivateKey(
      dataRepresentation: Data(contentsOf: Paths.sshKey),
      authenticationContext: context(reason: reason))
  }

  static func createAgreementKey(protection: Protection) throws
    -> SecureEnclave.P256.KeyAgreement.PrivateKey
  {
    try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: protection.accessControl())
  }

  static func loadAgreementKey(reason: String) throws
    -> SecureEnclave.P256.KeyAgreement.PrivateKey
  {
    try SecureEnclave.P256.KeyAgreement.PrivateKey(
      dataRepresentation: Data(contentsOf: Paths.credentialsKey),
      authenticationContext: context(reason: reason))
  }
}
