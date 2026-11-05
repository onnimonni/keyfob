import CryptoKit
import LocalAuthentication

/// Wraps the age plugin's Secure Enclave key so the Touch ID sheet names
/// the keyfob key in use. The reason is set right before the key is used,
/// since one plugin run may load several identities.
struct NamedAgeKey: SecureEnclaveP256PrivateKey {
  let key: SecureEnclave.P256.KeyAgreement.PrivateKey
  let context: LAContext

  var publicKey: P256.KeyAgreement.PublicKey { key.publicKey }
  var dataRepresentation: Data { key.dataRepresentation }

  func sharedSecretFromKeyAgreement(with publicKeyShare: P256.KeyAgreement.PublicKey) throws
    -> SharedSecret
  {
    context.localizedReason = AgePrompt.reason(p256Data: key.dataRepresentation)
    return try key.sharedSecretFromKeyAgreement(with: publicKeyShare)
  }
}
