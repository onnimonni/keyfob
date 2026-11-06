import CryptoKit
import LocalAuthentication

/// Wraps the age plugin's Secure Enclave key. The keyfob agent unlocks it
/// (one Touch ID policy for every key use, approvals reused per project);
/// without an agent this process asks itself, naming the key on the sheet.
/// Each key has its own context, so one approval never unlocks another.
struct NamedAgeKey: SecureEnclaveP256PrivateKey {
  let key: SecureEnclave.P256.KeyAgreement.PrivateKey
  let context: LAContext

  var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }
  var dataRepresentation: Data { key.dataRepresentation }

  func sharedSecretData(with publicKeyShare: P256.KeyAgreement.PublicKey) throws -> Data {
    switch AgentClient.agree(
      purpose: "age", handle: key.dataRepresentation, share: publicKeyShare.x963Representation,
      context: "")
    {
    case .result(let secret):
      return secret
    case .denied:
      throw KeyfobError("denied")
    case .unavailable:
      let action = Prompt.ageDecrypt(AgePrompt.caller, key: Key.age(matching: key.dataRepresentation))
      context.localizedReason = AgePrompt.caller.reason(action)
      do {
        let secret = try key.sharedSecretFromKeyAgreement(with: publicKeyShare)
          .withUnsafeBytes { Data($0) }
        AuditLog.record(action, caller: AgePrompt.caller, outcome: "allowed")
        return secret
      } catch {
        AuditLog.record(action, caller: AgePrompt.caller, outcome: "denied")
        throw error
      }
    }
  }
}
