import CryptoKit
import Foundation

let version = "0.3.1"

let usage = """
  keyfob \(version): Secure Enclave keys for SSH, git and age, unlocked with Touch ID
  https://github.com/onnimonni/keyfob

  Usage:
    keyfob init                          create the 'default' keys and config snippets
    keyfob new ssh|age NAME [--dangerous] create another key
    keyfob delete ssh|age NAME           delete a key (it is gone for good)
    keyfob list                          show keys and public keys
    keyfob status                        show approvals the agent still remembers
    keyfob lock                          forget all approvals now
    keyfob ssh-pubkey [NAME]             print an SSH public key
    keyfob age-recipient [NAME]          print an age recipient (age1se1...)
    keyfob ssh-agent [--socket PATH]     run the agent in the foreground
    keyfob install-ssh-config            use the agent from ~/.ssh/config
    keyfob install-launch-agent          start the agent at login (LaunchAgent)
    keyfob env                           print SSH_AUTH_SOCK and SOPS_AGE_KEY_FILE exports
    keyfob log                           show recent Touch ID requests and who made them
    keyfob git-credential get|store|erase

  Keys accept Touch ID or your password. The agent remembers an approval for
  a few minutes, but only for the same kind of request (commits in one repo,
  logins to one host, credentials for one host, age in one project) from the
  same app session; FORCE pushes, tags, forwarded requests and unknown apps
  always ask. Screen lock, sleep and `keyfob lock` forget every approval.
  --dangerous keys need Touch ID on every use and stop working when
  fingerprints change.

  Also runs as `git-credential-keyfob` (git credential helper) and as
  `age-plugin-se` (age plugin, compatible with age-plugin-se identities).
  """

func run(_ arguments: [String]) throws {
  let invokedAs = URL(fileURLWithPath: arguments[0]).lastPathComponent
  let args = Array(arguments.dropFirst())
  // Keys without Touch ID are for the test suite only, which sets KEYFOB_HOME
  let insecure = args.contains("--insecure-no-touch-id")
  if insecure, ProcessInfo.processInfo.environment["KEYFOB_HOME"] == nil {
    throw KeyfobError("--insecure-no-touch-id only works with KEYFOB_HOME set (tests)")
  }

  switch invokedAs {
  case "git-credential-keyfob":
    // With an agent, its child shows the Touch ID sheet; else this process does
    if args.first == "get", !AgentClient.isAvailable { Persona.becomeCallerApp() }
    try GitCredential.run(args.first ?? "")
    return
  case "age-plugin-se", "age-plugin-keyfob":
    if args.first == "--age-plugin=identity-v1", !AgentClient.isAvailable {
      Persona.becomeCallerApp()
    }
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
  case "list":
    try Setup.list()
  case "status":
    guard let active = AgentClient.status() else {
      throw KeyfobError("the agent is not running (\(AgentClient.socketPath))")
    }
    print(active.isEmpty ? "no remembered approvals" : active.joined(separator: "\n"))
  case "lock":
    guard AgentClient.lock() else {
      throw KeyfobError("the agent is not running (\(AgentClient.socketPath))")
    }
    print("forgot all approvals")
  case "ssh-agent":
    var socket = Paths.agentSocket.path
    if let index = args.firstIndex(of: "--socket"), index + 1 < args.count {
      socket = args[index + 1]
    }
    try SSHAgent(socketPath: socket).run()
  case "install-ssh-config":
    try Setup.installSSHConfig()
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
  case "__unlock" where args.count == 4:
    guard let mode = Persona.Mode(rawValue: args[1]), let protection = Protection(rawValue: args[2])
    else { throw KeyfobError("bad __unlock arguments") }
    try Persona.serveUnlocks(mode: mode, protection: protection, seconds: TimeInterval(args[3]) ?? 0)
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
}

func runAgePlugin(_ args: [String]) throws {
  let plugin = Plugin(crypto: CryptoKitCrypto(), stream: StandardIOStream())
  switch args.first {
  case "--age-plugin=recipient-v1":
    plugin.runRecipientV1()
  case "--age-plugin=identity-v1":
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
