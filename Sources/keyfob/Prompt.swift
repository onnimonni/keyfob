import Foundation

/// The text after "<App> is trying to" on the Touch ID sheet: a short title,
/// then one emoji-marked fact per line. Every value is caller-controlled and
/// cleaned to a single line, so callers cannot add lines of their own.
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
  /// Requests forwarded from another machine (`ssh -A`) are called out.
  static func sshLogin(_ caller: Caller, user: String, key: Key, forwarded: Bool) -> String {
    let forwarding = ("🔀", forwarded ? "forwarded from a remote host" : nil)
    // `git@` is implied for git hosting
    let login = user == "git" ? "" : "\(user)@"
    let host = caller.sshEndpoint.map {
      $0.port == "22" ? "\(login)\($0.host)" : "\(login)\($0.host):\($0.port)"
    }
    guard !forwarded, let path = caller.sshRemoteRepository else {
      return lines(
        "log in over SSH",
        [forwarding, ("🖥️", forwarded ? "as \(user)" : host), ("🔧", caller.initiatorLabel)],
        key: key.promptLine)
    }
    return lines(
      gitTitle(caller) ?? "use Git",
      [("🌐", host), ("📦", repositoryPath(path)), ("📁", caller.repository)]
        + pushFacts(caller),
      key: key.promptLine)
  }

  /// `url` is the credential git asked for: its host is what the token is
  /// released to, so it is shown even if git's remote claims something else.
  static func gitCredentials(_ caller: Caller, url: String) -> String {
    let requested = URLComponents(string: url)
    let remote = caller.httpRemote.flatMap(URLComponents.init(string:))
    let path =
      requested.map(\.path).flatMap { $0.isEmpty ? nil : $0 }
      ?? (remote?.host == requested?.host ? remote?.path : nil)
    return lines(
      gitTitle(caller) ?? "use Git credentials",
      [("🌐", requested?.host), ("📦", path.flatMap { $0.isEmpty ? nil : repositoryPath($0) })]
        + [("📁", caller.repository)] + pushFacts(caller),
      key: nil)
  }

  /// `org/repo` from `/org/repo.git`; absolute paths stay whole.
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

  /// `git push`, `git fetch`, …; a push that may rewrite or delete history is
  /// called out in the title.
  private static func gitTitle(_ caller: Caller) -> String? {
    if let push = caller.push, push.force || push.delete { return "FORCE push" }
    return caller.gitSubcommand.map { "git \($0)" }
  }

  /// Branch and destructive-push warning of a `git push`; nothing otherwise.
  private static func pushFacts(_ caller: Caller) -> [(String, String?)] {
    let push = caller.push
    let warning =
      push?.delete == true ? "may delete branches" : push?.force == true ? "may rewrite history" : nil
    return [("🌿", push?.branches), ("‼️", warning)]
  }

  /// `title:`, a 🚨 dangerous key right below it so it cannot be missed, the
  /// facts, any other key line, then the push branch and force warning last.
  static func lines(_ title: String, _ facts: [(String, String?)], key: String?) -> String {
    let present = facts.compactMap { icon, value in value.map { "\(icon) \(Caller.clean($0))" } }
    let keyLines = [key].compactMap { $0 }
    let isTrailing = { (line: String) in line.hasPrefix("🌿") || line.hasPrefix("‼️") }
    let ordered =
      keyLines.filter { $0.hasPrefix("🚨") }
      + present.filter { !isTrailing($0) }
      + keyLines.filter { !$0.hasPrefix("🚨") }
      + present.filter(isTrailing)
    let heading = Caller.clean(title)
    return ordered.isEmpty ? heading : ([heading + ":"] + ordered).joined(separator: "\n")
  }
}
