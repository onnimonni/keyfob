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

  /// Login over SSH; for git, phrased as the git operation with the server
  /// (`github.com`, `deploy@host:2222`) and repository path on their own lines.
  static func sshLogin(_ caller: Caller, user: String, key: Key) -> String {
    // `git@` is implied for git hosting
    let login = user == "git" ? "" : "\(user)@"
    let host = caller.sshEndpoint.map {
      $0.port == "22" ? "\(login)\($0.host)" : "\(login)\($0.host):\($0.port)"
    }
    guard let path = caller.sshRemoteRepository else {
      return lines(
        "log in over SSH", [("🖥️", host), ("🔧", caller.initiatorLabel)], key: key.promptLine)
    }
    let operation = gitTitle(caller) ?? "use Git"
    return lines(
      operation,
      [("🌐", host), ("📦", repositoryPath(path))] + pushFacts(caller)
        + [("📁", caller.repository)],
      key: key.promptLine)
  }

  static func gitCredentials(_ caller: Caller, url: String) -> String {
    let title = gitTitle(caller) ?? "use Git credentials"
    let remote = URLComponents(string: caller.httpRemote ?? url)
    return lines(
      title,
      [("🌐", remote?.host), ("📦", remote.map(\.path).flatMap { $0.isEmpty ? nil : repositoryPath($0) })]
        + pushFacts(caller) + [("📁", caller.repository)],
      key: nil)
  }

  /// `org/repo` from `/org/repo.git`; long absolute paths as `…/a/b/repo`.
  private static func repositoryPath(_ path: String) -> String {
    var path = path
    if path.hasSuffix(".git") { path.removeLast(4) }
    if path.hasPrefix("/"), path.split(separator: "/").count <= 2 { path.removeFirst() }
    return Caller.displayPath(path)
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

  /// `git push`, `git fetch`, …; a forced push is called out in the title.
  private static func gitTitle(_ caller: Caller) -> String? {
    caller.push?.force == true ? "FORCE push" : caller.gitSubcommand.map { "git \($0)" }
  }

  /// Force warning and branch of a `git push`; nothing for other commands.
  private static func pushFacts(_ caller: Caller) -> [(String, String?)] {
    [("‼️", caller.push?.force == true ? "may rewrite history" : nil), ("🌿", caller.push?.branches)]
  }

  /// `title:`, warnings (🚨 dangerous key, ‼️ force push) right below it so
  /// they cannot be missed, then the facts, then any other key line.
  static func lines(_ title: String, _ facts: [(String, String?)], key: String?) -> String {
    let present = facts.compactMap { icon, value in value.map { "\(icon) \($0)" } }
    let all = [key].compactMap { $0 } + present
    guard !all.isEmpty else { return title }
    let isWarning = { (line: String) in line.hasPrefix("🚨") || line.hasPrefix("‼️") }
    let warnings = all.filter(isWarning)
    let rest = present.filter { !isWarning($0) } + [key].compactMap { $0 }.filter { !isWarning($0) }
    return ([title + ":"] + warnings + rest).joined(separator: "\n")
  }
}
