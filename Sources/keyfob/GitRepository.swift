import Foundation

/// Current branch and origin of a work tree, read from the files in `.git`
/// (keyfob does not run git). Handles linked worktrees, whose `.git` is a file.
struct GitRepository {
  let branch: String?
  let origin: String?

  init?(workTree: String) {
    var directory = URL(fileURLWithPath: workTree)
    var gitDirectory: URL?
    while directory.path != "/" {
      let dotGit = directory.appendingPathComponent(".git")
      var isDirectory: ObjCBool = false
      if FileManager.default.fileExists(atPath: dotGit.path, isDirectory: &isDirectory) {
        if isDirectory.boolValue {
          gitDirectory = dotGit
        } else if let pointer = try? String(contentsOf: dotGit, encoding: .utf8),
          pointer.hasPrefix("gitdir: ")
        {
          let path = pointer.dropFirst(8).trimmingCharacters(in: .whitespacesAndNewlines)
          gitDirectory = URL(fileURLWithPath: path, relativeTo: directory).standardizedFileURL
        }
        break
      }
      directory.deleteLastPathComponent()
    }
    guard let gitDirectory else { return nil }

    let head = try? String(contentsOf: gitDirectory.appendingPathComponent("HEAD"), encoding: .utf8)
    branch = head.flatMap {
      let ref = $0.trimmingCharacters(in: .whitespacesAndNewlines)
      return ref.hasPrefix("ref: refs/heads/") ? String(ref.dropFirst(16)) : nil
    }

    // Linked worktrees keep config in the common directory
    var common = gitDirectory
    if let pointer = try? String(
      contentsOf: gitDirectory.appendingPathComponent("commondir"), encoding: .utf8)
    {
      common = URL(
        fileURLWithPath: pointer.trimmingCharacters(in: .whitespacesAndNewlines),
        relativeTo: gitDirectory
      ).standardizedFileURL
    }
    origin = (try? String(contentsOf: common.appendingPathComponent("config"), encoding: .utf8))
      .flatMap(GitRepository.originURL)
  }

  /// `url` of `[remote "origin"]` in a git config file.
  private static func originURL(_ config: String) -> String? {
    var inOrigin = false
    for line in config.split(whereSeparator: \.isNewline) {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      if trimmed.hasPrefix("[") {
        inOrigin = trimmed.replacingOccurrences(of: " ", with: "") == "[remote\"origin\"]"
      } else if inOrigin, trimmed.hasPrefix("url") {
        let parts = trimmed.split(separator: "=", maxSplits: 1)
        if parts.count == 2, parts[0].trimmingCharacters(in: .whitespaces) == "url" {
          return parts[1].trimmingCharacters(in: .whitespaces)
        }
      }
    }
    return nil
  }

  /// `github.com/org/repo` or `github.com:org/repo`: no scheme, no
  /// credentials, no `git@`, no `.git`.
  static func shortRemote(_ url: String) -> String {
    var short = url
    if let components = URLComponents(string: url), let host = components.host,
      components.scheme?.hasPrefix("http") == true
    {
      short = host + components.path
    }
    if short.hasPrefix("git@") { short.removeFirst(4) }
    if short.hasSuffix(".git") { short.removeLast(4) }
    return short
  }
}
