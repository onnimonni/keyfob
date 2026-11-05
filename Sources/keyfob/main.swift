import Foundation

let version = "0.1.0"

let usage = """
  keyfob \(version): Secure Enclave keys for SSH, git and age, unlocked with Touch ID
  https://github.com/onnimonni/keyfob

  Usage:
    keyfob init                       create missing keys and config snippets
    keyfob status                     show public keys
    keyfob ssh-agent [--socket PATH]  run the SSH agent in the foreground
    keyfob ssh-pubkey                 print the SSH public key
    keyfob age-recipient              print the age recipient (age1se1...)
    keyfob env                        print SSH_AUTH_SOCK and SOPS_AGE_KEY_FILE exports
    keyfob log                        show recent Touch ID requests and who made them
    keyfob install-launch-agent       write a LaunchAgent that runs the SSH agent
    keyfob git-credential get|store|erase

  Also runs as `git-credential-keyfob` (git credential helper) and as
  `age-plugin-se` (age plugin, compatible with age-plugin-se identities).
  """

func run(_ arguments: [String]) throws {
  let invokedAs = URL(fileURLWithPath: arguments[0]).lastPathComponent
  let args = Array(arguments.dropFirst())

  switch invokedAs {
  case "git-credential-keyfob":
    try GitCredential.run(args.first ?? "")
    return
  case "age-plugin-se", "age-plugin-keyfob":
    try runAgePlugin(args)
    return
  default:
    break
  }

  switch args.first {
  case "init":
    let protection: Protection = args.contains("--insecure-no-touch-id") ? .none : .touchID
    try Setup.initialize(protection: protection)
  case "status":
    try Setup.status()
  case "ssh-agent":
    var socket = Paths.agentSocket.path
    if let index = args.firstIndex(of: "--socket"), index + 1 < args.count {
      socket = args[index + 1]
    }
    try SSHAgent(socketPath: socket).run()
  case "ssh-pubkey":
    print(try Setup.sshPublicKey())
  case "age-recipient":
    print(try Setup.ageRecipient())
  case "env":
    print(Setup.environment)
  case "log":
    try AuditLog.show(lines: 50)
  case "install-launch-agent":
    try Setup.installLaunchAgent()
  case "git-credential":
    try GitCredential.run(args.dropFirst().first ?? "")
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
  static var action: String { caller.targetFile.map { "decrypt \($0)" } ?? "decrypt a file with age" }
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
    throw KeyfobError("this is keyfob's age plugin; create keys with `keyfob init`")
  }
}

do {
  try run(CommandLine.arguments)
} catch {
  FileHandle.standardError.write(Data("keyfob: \(error.localizedDescription)\n".utf8))
  exit(1)
}
