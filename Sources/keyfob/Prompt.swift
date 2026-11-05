import Foundation

/// The text after "<App> is trying to" on the Touch ID sheet: a short title,
/// then one emoji-marked fact per line, ending with the key that will be
/// used, so the period macOS appends closes a sentence.
enum Prompt {
  static func gitSigning(_ caller: Caller, tag: Bool, key: Key) -> String {
    let repository = caller.repositoryPath.flatMap(GitRepository.init(workTree:))
    return lines(
      tag ? "sign a Git tag" : "sign a Git commit",
      [
        ("📝", caller.signedSubject),
        ("📁", caller.repository),
        ("📦", repository?.origin.map(GitRepository.shortRemote)),
      ],
      key: key.promptLine)
  }

  /// Login over SSH; for git, phrased as the git operation with its remote in
  /// `git clone` form (`git@github.com:org/repo`).
  static func sshLogin(_ caller: Caller, user: String, key: Key) -> String {
    let endpoint = caller.sshEndpoint
    // `git@` is implied for git hosting, as in `github.com:org/repo`
    let login = user == "git" ? "" : "\(user)@"
    let host = endpoint.map {
      $0.port == "22" ? "\(login)\($0.host)" : "\(login)\($0.host):\($0.port)"
    }
    guard let endpoint, var path = caller.sshRemoteRepository else {
      return lines(
        "log in over SSH", [("🖥️", host), ("🔧", caller.initiatorLabel)], key: key.promptLine)
    }
    if path.hasSuffix(".git") { path.removeLast(4) }
    let remote =
      endpoint.port == "22"
      ? "\(login)\(endpoint.host):\(path)"
      : "ssh://\(login)\(endpoint.host):\(endpoint.port)/\(path.drop { $0 == "/" })"
    let operation = caller.gitSubcommand.map { "git \($0)" } ?? "use Git"
    return lines(
      operation,
      [("📦", remote)] + pushFacts(caller) + [("📁", caller.repository)],
      key: key.promptLine)
  }

  static func gitCredentials(_ caller: Caller, url: String) -> String {
    let title = caller.gitSubcommand.map { "git \($0)" } ?? "use Git credentials"
    return lines(
      title,
      [("📦", GitRepository.shortRemote(caller.httpRemote ?? url))] + pushFacts(caller)
        + [("📁", caller.repository)],
      key: nil)
  }

  /// `key` is nil when the identity is not one of keyfob's (or not yet known).
  static func ageDecrypt(_ caller: Caller, key: Key?) -> String {
    let directory = caller.initiator?.workingDirectory
    var file = caller.targetFile.map(Caller.displayPath)
    if let directory, let absolute = caller.targetFile, absolute.hasPrefix(directory + "/") {
      file = String(absolute.dropFirst(directory.count + 1))
    }
    let tool = caller.initiatorLabel.flatMap { $0 == "age" ? nil : $0 }
    return lines(
      "decrypt a file using age",
      [("📄", file), ("📁", directory.map(Caller.displayPath)), ("🔧", tool)],
      key: key.map(\.promptLine) ?? "🔑 using age-plugin-se key")
  }

  /// Branch and force warning of a `git push`; nothing for other commands.
  private static func pushFacts(_ caller: Caller) -> [(String, String?)] {
    [("🌿", caller.push?.branches), ("⚠️", caller.push?.force == true ? "force: may overwrite" : nil)]
  }

  /// `title:`, warnings (🚨 dangerous key, ⚠️ force push) right below it so
  /// they cannot be missed, then the facts, then any other key line.
  static func lines(_ title: String, _ facts: [(String, String?)], key: String?) -> String {
    let present = facts.compactMap { icon, value in value.map { "\(icon) \($0)" } }
    let all = [key].compactMap { $0 } + present
    guard !all.isEmpty else { return title }
    let isWarning = { (line: String) in line.hasPrefix("🚨") || line.hasPrefix("⚠️") }
    let warnings = all.filter(isWarning)
    let rest = present.filter { !isWarning($0) } + [key].compactMap { $0 }.filter { !isWarning($0) }
    return ([title + ":"] + warnings + rest).joined(separator: "\n")
  }
}
