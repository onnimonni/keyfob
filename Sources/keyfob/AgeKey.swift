import CryptoKit
import LocalAuthentication

/// Wraps the age plugin's Secure Enclave key so the Touch ID sheet names
/// the keyfob key in use, and the audit log records the outcome. Each key
/// has its own context, so one approval never unlocks another identity.
struct NamedAgeKey: SecureEnclaveP256PrivateKey {
  let key: SecureEnclave.P256.KeyAgreement.PrivateKey
  let context: LAContext

  var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }
  var dataRepresentation: Data { key.dataRepresentation }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
  {
    let named = Key.age(matching: key.dataRepresentation)
    let action = Prompt.ageDecrypt(AgePrompt.caller, key: named)
    context.localizedReason = AgePrompt.caller.reason(action)
    do {
      let secret = try key.sharedSecretFromKeyAgreement(with: publicKeyShare)
      AuditLog.record(action, caller: AgePrompt.caller, outcome: "allowed")
      return secret
    } catch {
      AuditLog.record(action, caller: AgePrompt.caller, outcome: "denied")
      throw error
    }
  }
}
