import CryptoKit
import Foundation
import SystemConfiguration

/// Key management commands and the config snippets git and ssh include.
enum Setup {
  /// `keyfob init`: the `default` SSH and age keys plus the git credentials
  /// key, whichever are missing.
  static func initialize(insecure: Bool) throws {
    try SecureEnclaveKeys.requireSecureEnclave()
    try Paths.ensureDirectory(Paths.home)

    for kind in Key.Kind.allCases where Key.named(kind, Key.defaultName) == nil {
      let key = try Key.create(kind, Key.defaultName, protection: insecure ? .none : .normal)
      print("created \(kind.label) key '\(key.name)'")
    }
    if !Paths.exists(Paths.credentialsKey) {
      try SecureEnclaveKeys.createCredentialsKey(protection: insecure ? .none : .touchID)
      print("created git credentials key")
    }
    try writeConfig()

    print("")
    try list()
    print(
      """

      Finish setup (skip what your nix module already does):
        git config --global include.path \(Paths.gitConfig.path)
        echo 'Include \(Paths.sshConfig.path)' >> ~/.ssh/config
        keyfob install-launch-agent
        echo 'eval "$(keyfob env)"' >> ~/.zshrc
      Then add the 'default' SSH key to GitHub as both authentication and signing key.
      """)
  }

  /// `keyfob new ssh|age NAME [--dangerous]`
  static func create(_ kind: Key.Kind, _ name: String, dangerous: Bool, insecure: Bool) throws {
    let protection: Protection = insecure ? .none : dangerous ? .dangerous : .normal
    let key = try Key.create(kind, name, protection: protection)
    try writeConfig()
    print("created \(key.isDangerous ? "dangerous " : "")\(kind.label) key '\(name)'")
    print(try key.publicKey())
    if kind == .ssh {
      print(
        """

        Use it for some hosts in ~/.ssh/config:
          Host prod-*
            IdentityFile \(key.publicKeyFile.path)
            IdentitiesOnly yes
        """)
    } else {
      print("\nDecrypt with: age -d -i \(key.handle.path)")
    }
  }

  static func delete(_ kind: Key.Kind, _ name: String) throws {
    guard let key = Key.named(kind, name) else {
      throw KeyfobError("no \(kind.label) key '\(name)'")
    }
    try key.delete()
    try writeConfig()
    print("deleted \(kind.label) key '\(name)'")
  }

  static func list() throws {
    for kind in Key.Kind.allCases {
      for key in Key.all(kind) {
        let tag = key.isDangerous ? " 🚨 dangerous" : key.protection == .none ? " (no Touch ID)" : ""
        print("\(kind.rawValue) \(key.name)\(tag)")
        print("  \(try key.publicKey())")
      }
    }
    print("git credentials key: \(Paths.exists(Paths.credentialsKey) ? "present" : "missing")")
    print("agent socket: \(Paths.agentSocket.path)")
  }

  static func publicKey(_ kind: Key.Kind, _ name: String?) throws -> String {
    let name = name ?? Key.defaultName
    guard let key = Key.named(kind, name) else {
      throw KeyfobError("no \(kind.label) key '\(name)', see `keyfob list`")
    }
    return try key.publicKey()
  }

  static var environment: String {
    """
    export SSH_AUTH_SOCK=\(shellQuote(Paths.agentSocket.path))
    export SOPS_AGE_KEY_FILE=\(shellQuote(Key(kind: .age, name: Key.defaultName, protection: .normal).handle.path))
    """
  }

  static func installLaunchAgent() throws {
    let label = "build.flaky.keyfob"
    let plist: [String: Any] = [
      "Label": label,
      "ProgramArguments": [try executablePath(), "ssh-agent"],
      "RunAtLoad": true,
      "KeepAlive": true,
      "ProcessType": "Interactive",
      "StandardErrorPath": NSHomeDirectory() + "/Library/Logs/keyfob-agent.log",
    ]
    let url = URL(fileURLWithPath: NSHomeDirectory())
      .appendingPathComponent("Library/LaunchAgents/\(label).plist")
    try FileManager.default.createDirectory(
      at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
      .write(to: url, options: .atomic)
    print("wrote \(url.path)\nstart it with:\n  launchctl bootstrap gui/$(id -u) \(url.path)")
  }

  /// Puts `Include ~/.config/keyfob/ssh_config` at the top of ~/.ssh/config,
  /// so keyfob's IdentityAgent wins over later ones (ssh uses the first value
  /// it sees). Idempotent; keeps a backup; refuses a symlinked (managed) file.
  static func installSSHConfig() throws {
    try writeConfig()
    let home = ProcessInfo.processInfo.environment["HOME"].flatMap { $0.isEmpty ? nil : $0 }
    let config = URL(fileURLWithPath: home ?? NSHomeDirectory()).appendingPathComponent(".ssh/config")
    let include = "Include \(Paths.sshConfig.path)"
    let manager = FileManager.default

    if let destination = try? manager.destinationOfSymbolicLink(atPath: config.path) {
      throw KeyfobError(
        """
        ~/.ssh/config is a symlink (\(destination)), probably managed by nix or a dotfiles tool.
        Add this line at its top there instead:
          \(include)
        or with home-manager: programs.keyfob.enable = true (sets SSH_AUTH_SOCK) and
          programs.ssh.includes = [ "\(Paths.sshConfig.path)" ];
        """)
    }
    let existing = (try? String(contentsOf: config, encoding: .utf8)) ?? ""
    if existing.split(whereSeparator: \.isNewline).contains(where: {
      $0.trimmingCharacters(in: .whitespaces) == include
    }) {
      print("~/.ssh/config already includes \(Paths.sshConfig.path)")
      return
    }
    if !existing.isEmpty {
      let backup = config.path + ".keyfob-backup"
      try? manager.removeItem(atPath: backup)
      try manager.copyItem(atPath: config.path, toPath: backup)
      print("backed up ~/.ssh/config to \(backup)")
    }
    try manager.createDirectory(
      at: config.deletingLastPathComponent(), withIntermediateDirectories: true,
      attributes: [.posixPermissions: 0o700])
    let header = "# Added by keyfob (https://github.com/onnimonni/keyfob)\n\(include)\n\n"
    try Paths.writePrivate(Data((header + existing).utf8), to: config)
    print(
      """
      added to the top of ~/.ssh/config:
        \(include)
      Make sure the agent runs: keyfob install-launch-agent
      """)
  }

  static var hostName: String {
    SCDynamicStoreCopyLocalHostName(nil) as String? ?? "mac"
  }

  /// gitconfig signs with the `default` SSH key; allowed_signers lists all.
  private static func writeConfig() throws {
    let email = ProcessInfo.processInfo.environment["KEYFOB_EMAIL"] ?? "*"
    let signers = try Key.all(.ssh).map { "\(email) \(try $0.publicKey())\n" }.joined()
    try Paths.writePrivate(Data(signers.utf8), to: Paths.allowedSigners)
    let signingKey = Key(kind: .ssh, name: Key.defaultName, protection: .normal).publicKeyFile
    try Paths.writePrivate(
      Data(
        """
        # Generated by keyfob (https://github.com/onnimonni/keyfob)
        [user]
        \tsigningkey = \(signingKey.path)
        [gpg]
        \tformat = ssh
        [gpg "ssh"]
        \tallowedSignersFile = \(Paths.allowedSigners.path)
        [commit]
        \tgpgsign = true
        [tag]
        \tgpgsign = true
        [credential]
        \thelper =
        \thelper = keyfob

        """.utf8), to: Paths.gitConfig)
    try Paths.writePrivate(
      Data(
        """
        # Generated by keyfob (https://github.com/onnimonni/keyfob)
        Host *
          IdentityAgent \(Paths.agentSocket.path)

        """.utf8), to: Paths.sshConfig)
  }

  /// Absolute path of this binary without resolving symlinks, so a stable
  /// profile link (e.g. ~/.nix-profile/bin/keyfob) survives upgrades.
  private static func executablePath() throws -> String {
    let argv0 = CommandLine.arguments[0]
    if argv0.contains("/") {
      return URL(
        fileURLWithPath: argv0,
        relativeTo: URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
      ).standardizedFileURL.path
    }
    let path = ProcessInfo.processInfo.environment["PATH"] ?? ""
    for dir in path.split(separator: ":") {
      let candidate = "\(dir)/\(argv0)"
      if FileManager.default.isExecutableFile(atPath: candidate) { return candidate }
    }
    throw KeyfobError("cannot find \(argv0) in PATH")
  }

  private static func shellQuote(_ value: String) -> String {
    "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'"
  }
}
