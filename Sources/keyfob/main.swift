import CryptoKit
import Foundation

let version = "0.2.0"

let usage = """
  keyfob \(version): Secure Enclave keys for SSH, git and age, unlocked with Touch ID
  https://github.com/onnimonni/keyfob

  Usage:
    keyfob init                          create the 'default' keys and config snippets
    keyfob new ssh|age NAME [--dangerous] create another key
    keyfob delete ssh|age NAME           delete a key (it is gone for good)
    keyfob list                          show keys and public keys
    keyfob ssh-pubkey [NAME]             print an SSH public key
    keyfob age-recipient [NAME]          print an age recipient (age1se1...)
    keyfob ssh-agent [--socket PATH]     run the SSH agent in the foreground
    keyfob env                           print SSH_AUTH_SOCK and SOPS_AGE_KEY_FILE exports
    keyfob log                           show recent Touch ID requests and who made them
    keyfob install-launch-agent          write a LaunchAgent that runs the SSH agent
    keyfob git-credential get|store|erase

  Keys accept Touch ID or your password, and the SSH agent lets one approval
  cover 5 minutes per app and key. --dangerous keys need Touch ID on every use
  and stop working when fingerprints change.

  Also runs as `git-credential-keyfob` (git credential helper) and as
  `age-plugin-se` (age plugin, compatible with age-plugin-se identities).
  """

func run(_ arguments: [String]) throws {
  let invokedAs = URL(fileURLWithPath: arguments[0]).lastPathComponent
  let args = Array(arguments.dropFirst())
  let insecure = args.contains("--insecure-no-touch-id")

  switch invokedAs {
  case "git-credential-keyfob":
    if args.first == "get" { Persona.becomeCallerApp() }
    try GitCredential.run(args.first ?? "")
    return
  case "age-plugin-se", "age-plugin-keyfob":
    if args.first == "--age-plugin=identity-v1" { Persona.becomeCallerApp() }
    try runAgePlugin(args)
    return
  default:
    break
  }

  /// `ssh`/`age` and the name after a key command
  func keyArguments() throws -> (Key.Kind, String) {
    let operands = args.dropFirst().filter { !$0.hasPrefix("--") }
    guard operands.count == 2, let kind = Key.Kind(rawValue: operands[operands.startIndex]) else {
      throw KeyfobError("usage: keyfob \(args[0]) ssh|age NAME")
    }
    return (kind, operands[operands.startIndex + 1])
  }
  let operand = args.dropFirst().first { !$0.hasPrefix("--") }

  switch args.first {
  case "init":
    try Setup.initialize(insecure: insecure)
  case "new":
    let (kind, name) = try keyArguments()
    try Setup.create(kind, name, dangerous: args.contains("--dangerous"), insecure: insecure)
  case "delete":
    let (kind, name) = try keyArguments()
    try Setup.delete(kind, name)
  case "list", "status":
    try Setup.list()
  case "ssh-agent":
    var socket = Paths.agentSocket.path
    if let index = args.firstIndex(of: "--socket"), index + 1 < args.count {
      socket = args[index + 1]
    }
    try SSHAgent(socketPath: socket).run()
  case "ssh-pubkey":
    print(try Setup.publicKey(.ssh, operand))
  case "age-recipient":
    print(try Setup.publicKey(.age, operand))
  case "env":
    print(Setup.environment)
  case "log":
    try AuditLog.show(lines: 50)
  case "install-launch-agent":
    try Setup.installLaunchAgent()
  case "git-credential":
    try GitCredential.run(args.dropFirst().first ?? "")
  case "__sign" where args.count == 3:
    try Persona.signOnce(keyName: args[1], reason: args[2])
  case "__signer" where args.count == 3:
    try Persona.serveSignatures(keyName: args[1], reuseSeconds: TimeInterval(args[2]) ?? 0)
  case "version", "--version":
    print(version)
  case nil, "help", "--help", "-h":
    print(usage)
  case let command?:
    throw KeyfobError("unknown command `\(command)`, see `keyfob help`")
  }
}

/// Touch ID text for age decryption; the parent is age itself or sops.
enum AgePrompt {
  static let caller = Caller.parent

  static var action: String { Prompt.ageDecrypt(caller, key: nil) }

  /// Named after the keyfob age key that holds `p256Data`.
  static func reason(p256Data: Data) -> String {
    caller.reason(Prompt.ageDecrypt(caller, key: Key.age(matching: p256Data)))
  }
}

func runAgePlugin(_ args: [String]) throws {
  let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
  switch args.first {
  case "--age-plugin=recipient-v1":
    plugin.runRecipientV1()
  case "--age-plugin=identity-v1":
    // The plugin protocol hides the outcome from us, so log the request
    AuditLog.record(AgePrompt.action, caller: AgePrompt.caller, outcome: "requested")
    plugin.runIdentityV1()
  default:
    throw KeyfobError("this is keyfob's age plugin; create keys with `keyfob new age NAME`")
  }
}

do {
  try run(CommandLine.arguments)
} catch {
  FileHandle.standardError.write(Data("keyfob: \(error.localizedDescription)\n".utf8))
  exit(1)
}
