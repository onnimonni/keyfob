import Foundation

/// The text after "<App> is trying to" on the Touch ID sheet: a short title,
/// then one emoji-marked fact per line, ending with the key that will be
/// used, so the period macOS appends closes a sentence.
enum Prompt {
  static func gitSigning(_ caller: Caller, tag: Bool) -> String {
    let repository = caller.repositoryPath.flatMap(GitRepository.init(workTree:))
    return lines(
      tag ? "sign a Git tag" : "sign a Git commit",
      [
        ("📝", caller.signedSubject),
        ("📁", caller.repository),
        ("🌿", repository?.branch),
        ("📦", repository?.origin.map(GitRepository.shortRemote)),
      ],
      key: "SSH")
  }

  /// Login over SSH; for git, phrased as the git operation with its remote in
  /// `git clone` form (`git@github.com:org/repo`).
  static func sshLogin(_ caller: Caller, user: String) -> String {
    let endpoint = caller.sshEndpoint
    // `git@` is implied for git hosting, as in `github.com:org/repo`
    let login = user == "git" ? "" : "\(user)@"
    let host = endpoint.map {
      $0.port == "22" ? "\(login)\($0.host)" : "\(login)\($0.host):\($0.port)"
    }
    guard let endpoint, var path = caller.sshRemoteRepository else {
      return lines(
        "log in over SSH", [("🖥️", host), ("🔧", caller.initiatorLabel)], key: "SSH")
    }
    if path.hasSuffix(".git") { path.removeLast(4) }
    let remote =
      endpoint.port == "22"
      ? "\(login)\(endpoint.host):\(path)"
      : "ssh://\(login)\(endpoint.host):\(endpoint.port)/\(path.drop { $0 == "/" })"
    let operation = caller.gitSubcommand.map { "git \($0)" } ?? "use Git"
    return lines(
      "\(operation) over SSH", [("📦", remote), ("📁", caller.repository)], key: "SSH")
  }

  static func gitCredentials(_ caller: Caller, url: String) -> String {
    let title = caller.gitSubcommand.map { "git \($0) over HTTPS" } ?? "use Git credentials"
    return lines(
      title,
      [("📦", GitRepository.shortRemote(caller.httpRemote ?? url)), ("📁", caller.repository)],
      key: "Git credentials")
  }

  static func ageDecrypt(_ caller: Caller) -> String {
    let directory = caller.initiator?.workingDirectory
    var file = caller.targetFile.map(Caller.displayPath)
    if let directory, let absolute = caller.targetFile, absolute.hasPrefix(directory + "/") {
      file = String(absolute.dropFirst(directory.count + 1))
    }
    let tool = caller.initiatorLabel.flatMap { $0 == "age" ? nil : $0 }
    return lines(
      "decrypt a file using age",
      [("📄", file), ("📁", directory.map(Caller.displayPath)), ("🔧", tool)],
      key: "age")
  }

  /// `title:`, the present facts, then the key line.
  private static func lines(_ title: String, _ facts: [(String, String?)], key: String) -> String {
    let present = facts.compactMap { icon, value in value.map { "\(icon) \($0)" } }
    return ([title + ":"] + present + ["🔑 using your '\(key)' key"]).joined(separator: "\n")
  }
}
