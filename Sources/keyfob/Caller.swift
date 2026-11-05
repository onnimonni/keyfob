import Darwin
import Foundation

/// Who is asking: the chain of processes behind a request, condensed for the
/// Touch ID sheet and written in full to the audit log.
///
/// Process names and arguments are controlled by the caller, so this is
/// context for the user, not authentication.
struct Caller {
  struct Process {
    let pid: pid_t
    let parent: pid_t
    /// Executable path from the kernel, not the caller-controlled argv[0]
    let path: String
    let arguments: [String]

    /// Basename, unwrapping nix wrappers (`.git-wrapped` → `git`)
    var name: String {
      var name = URL(fileURLWithPath: path).lastPathComponent
      if name.hasPrefix("."), name.hasSuffix("-wrapped") {
        name = String(name.dropFirst().dropLast("-wrapped".count))
      }
      return name
    }

    /// First argument that is not an option (or an option's value).
    func firstOperand(optionsWithValues: Set<String>) -> String? {
      var rest = arguments.dropFirst()
      while let argument = rest.first, argument.hasPrefix("-") {
        rest = rest.dropFirst(optionsWithValues.contains(argument) ? 2 : 1)
      }
      return rest.first
    }

    var gitSubcommand: String? {
      name == "git" ? firstOperand(optionsWithValues: ["-c", "-C"]) : nil
    }

    var workingDirectory: String? {
      var info = proc_vnodepathinfo()
      let size = Int32(MemoryLayout<proc_vnodepathinfo>.size)
      guard proc_pidinfo(pid, PROC_PIDVNODEPATHINFO, 0, &info, size) == size else { return nil }
      return withUnsafeBytes(of: info.pvi_cdir.vip_path) {
        String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self)
      }
    }
  }

  /// Nearest first, ending before launchd.
  let chain: [Process]

  init(pid: pid_t) {
    var chain: [Process] = []
    var next = pid
    while next > 1, chain.count < 16, let process = Caller.lookup(next) {
      chain.append(process)
      next = process.parent
    }
    self.chain = chain
  }

  /// The process that spawned this one (git for the credential helper, age/sops for the plugin).
  static var parent: Caller { Caller(pid: getppid()) }

  // MARK: What the user sees

  /// Text for the Touch ID sheet. macOS starts it with the executable's name
  /// (`speaker`). When that is already the app (see Persona) the action follows
  /// directly, else the app is named: "keyfob is trying to let iTerm sign …".
  func reason(_ action: String, speaker: String = Persona.currentName) -> String {
    let named = app.map { Persona.fileName($0) == speaker ? action : "let \($0) \(action)" }
    // Line breaks in `action` are deliberate (see Prompt); clean each line
    var text = (named ?? action)
      .split(separator: "\n", omittingEmptySubsequences: false)
      .map { Caller.clean(String($0), limit: 200) }.joined(separator: "\n")
    // macOS appends a period; a lone "." on its own line looks broken
    while text.hasSuffix("\n") { text.removeLast() }
    return text
  }

  /// `for git push in Claude Code`
  var origin: String? {
    let command = initiator.map(Caller.label)
    switch (command, app) {
    case let (command?, app?) where command.lowercased() != app.lowercased():
      return "for \(command) in \(app)"
    case let (_, app?): return "in \(app)"
    case let (command?, nil): return "for \(command)"
    default: return nil
    }
  }

  /// The command the user actually ran: the nearest process that is not a
  /// shell, wrapper or helper, looking no further than the app or the
  /// terminal login that started it.
  var initiator: Process? {
    for process in chain {
      if Caller.agentName(process) != nil || Caller.bundleName(process) != nil
        || process.name == "login"
      {
        return nil
      }
      if !Caller.isPlumbing(process) { return process }
    }
    return nil
  }

  /// Where it ran: a coding agent if one is in the chain, else the app bundle
  /// (iTerm, Visual Studio Code, …) the chain descends from.
  var app: String? {
    chain.lazy.compactMap(Caller.agentName).first
      ?? chain.lazy.compactMap(Caller.bundleName).first
  }

  /// Name the Touch ID sheet is titled with: the app, or `unknown` so an
  /// unrecognised caller stands out.
  var displayApp: String { app ?? "unknown" }

  /// Work tree the git operation runs in (git chdirs to it), absolute.
  var repositoryPath: String? {
    chain.first(where: { $0.name.hasPrefix("git") })?.workingDirectory
  }

  /// Work tree as `~/Projects/x`.
  var repository: String? { repositoryPath.map(Caller.displayPath) }

  /// Directory the initiating command runs in (the project for sops/age).
  var initiatorDirectory: String? {
    initiator?.workingDirectory.map(Caller.displayPath)
  }

  /// File named last on the initiator's command line, resolved against its
  /// working directory: `sops -d secrets/x.yaml` → `/Users/me/.dotfiles/secrets/x.yaml`.
  var targetFile: String? {
    let valueOptions: Set<String> = [
      "-i", "-o", "-r", "-R", "--identity", "--output", "--recipient", "--recipients-file",
      "--input-type", "--output-type", "--config",
    ]
    guard let initiator, initiator.arguments.count > 1,
      let last = initiator.arguments.last, !last.hasPrefix("-"),
      !valueOptions.contains(initiator.arguments[initiator.arguments.count - 2])
    else { return nil }
    let absolute =
      last.hasPrefix("/") ? last : (initiator.workingDirectory.map { "\($0)/\(last)" } ?? last)
    return URL(fileURLWithPath: absolute).standardizedFileURL.path
  }

  /// `~/Projects/x`: the full path, never shortened, since the user decides on it.
  static func displayPath(_ path: String) -> String {
    let home = NSHomeDirectory()
    guard path == home || path.hasPrefix(home + "/") else { return path }
    return "~" + path.dropFirst(home.count)
  }

  var gitSubcommand: String? {
    chain.lazy.compactMap(\.gitSubcommand).first {
      !$0.hasPrefix("credential") && !$0.hasPrefix("remote-")
    }
  }

  /// What `git push` updates: the destinations of its refspecs
  /// (`git push origin HEAD:main` → `main`), else the current branch, and
  /// whether it is forced (`--force`, `--force-with-lease`, `+refspec`).
  var push: (branches: String?, force: Bool)? {
    guard let push = chain.first(where: { $0.gitSubcommand == "push" }) else { return nil }
    var arguments = push.arguments.dropFirst()
    arguments = arguments.drop { $0 != "push" }.dropFirst()  // skip `git -C dir -c x=y`
    let valueOptions: Set<String> = ["--repo", "-o", "--push-option", "--receive-pack", "--exec"]
    var operands: [String] = []
    var force = false
    var skipNext = false
    for argument in arguments {
      if skipNext {
        skipNext = false
      } else if valueOptions.contains(argument) {
        skipNext = true
      } else if argument.hasPrefix("-") {
        if ["-f", "--force"].contains(argument) || argument.hasPrefix("--force-with-lease") {
          force = true
        }
        if ["--all", "--mirror", "--tags"].contains(argument) { operands.append(argument) }
      } else {
        operands.append(argument)
      }
    }
    // The first operand is the remote, unless only flags like --all were given
    let refspecs = operands.first?.hasPrefix("--") == true ? operands : Array(operands.dropFirst())
    var branches = refspecs.map { refspec -> String in
      if refspec.hasPrefix("+") { force = true }
      let destination = refspec.split(separator: ":", omittingEmptySubsequences: false).last
        .map(String.init) ?? refspec
      return destination.replacingOccurrences(of: "refs/heads/", with: "")
        .trimmingCharacters(in: CharacterSet(charactersIn: "+"))
    }.joined(separator: ", ")
    if branches.isEmpty,
      let current = push.workingDirectory.flatMap(GitRepository.init(workTree:))?.branch
    {
      branches = current
    }
    return (branches.isEmpty ? nil : branches, force)
  }

  /// Host and port from `ssh -o … -p 2222 git@github.com git-upload-pack '…'`.
  var sshEndpoint: (host: String, port: String)? {
    let options: Set<String> = [
      "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
      "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w",
    ]
    guard let ssh = chain.first(where: { $0.name == "ssh" }),
      var host = ssh.firstOperand(optionsWithValues: options)
    else { return nil }
    var port = "22"
    if let index = ssh.arguments.firstIndex(of: "-p"), index + 1 < ssh.arguments.count {
      port = ssh.arguments[index + 1]
    }
    if host.hasPrefix("ssh://") {
      host = String(host.dropFirst(6).prefix { $0 != "/" })
      if let colon = host.lastIndex(of: ":") {
        port = String(host[host.index(after: colon)...])
        host = String(host[..<colon])
      }
    }
    host = host.split(separator: "@").last.map(String.init) ?? host
    return (host, port)
  }

  /// URL git is talking to, from `git-remote-https origin https://…`, without
  /// any userinfo.
  var httpRemote: String? {
    guard let remote = chain.first(where: { $0.name.hasPrefix("git-remote-") }),
      remote.arguments.count > 2, var url = URLComponents(string: remote.arguments[2])
    else { return nil }
    url.user = nil
    url.password = nil
    return url.string
  }

  /// `/org/repo.git` from ssh's remote command `git-receive-pack '/org/repo.git'`.
  var sshRemoteRepository: String? {
    guard let command = chain.first(where: { $0.name == "ssh" })?.arguments.last,
      command.hasPrefix("git-"), let start = command.firstIndex(of: "'")
    else { return nil }
    return String(command[command.index(after: start)...].prefix { $0 != "'" })
  }

  // MARK: Audit log

  /// Every process with pid and full command line.
  var detail: String {
    chain.map { process in
      let command = process.arguments.isEmpty
        ? process.path : process.arguments.joined(separator: " ")
      return "\(process.pid):\(Caller.clean(command, limit: 200))"
    }.joined(separator: " < ")
  }

  // MARK: Helpers

  /// Coding agents, shown by their command name (`claude`, `codex`, …)
  private static let agents: Set<String> = [
    "claude", "codex", "gemini", "cursor-agent", "opencode", "aider", "amp",
  ]

  private static func agentName(_ process: Process) -> String? {
    agents.contains(process.name) ? process.name : nil
  }

  /// Outermost .app in the executable path, so helpers map to their product.
  private static func bundleName(_ process: Process) -> String? {
    guard let range = process.path.range(of: ".app/") else { return nil }
    return URL(fileURLWithPath: String(process.path[..<range.lowerBound])).lastPathComponent
  }

  /// `git push`, `sops`, …
  var initiatorLabel: String? { initiator.map(Caller.label) }

  private static func label(_ process: Process) -> String {
    process.gitSubcommand.map { "git \($0)" } ?? process.name
  }

  private static let plumbing: Set<String> = [
    "keyfob", "git-credential-keyfob", "age-plugin-se", "xcrun", "ssh", "ssh-keygen",
    "timeout", "env", "nice", "coreutils", "sh", "bash", "zsh", "dash", "fish", "login",
  ]

  private static func isPlumbing(_ process: Process) -> Bool {
    plumbing.contains(process.name)
      || process.name.hasPrefix("git-remote-")
      || process.gitSubcommand?.hasPrefix("credential") == true
  }

  /// One line, no control characters, bounded length.
  static func clean(_ text: String, limit: Int = 60) -> String {
    let line = String(
      text.unicodeScalars.map { CharacterSet.controlCharacters.contains($0) ? " " : Character($0) })
    return line.count > limit ? String(line.prefix(limit - 1)) + "…" : line
  }

  private static func lookup(_ pid: pid_t) -> Process? {
    var info = kinfo_proc()
    var size = MemoryLayout<kinfo_proc>.size
    var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
    guard sysctl(&mib, u_int(mib.count), &info, &size, nil, 0) == 0, size > 0 else {
      return nil
    }
    var pathBuffer = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
    let path =
      proc_pidpath(pid, &pathBuffer, UInt32(pathBuffer.count)) > 0
      ? String(cString: pathBuffer)
      : withUnsafeBytes(of: info.kp_proc.p_comm) {
        String(decoding: $0.prefix(while: { $0 != 0 }), as: UTF8.self)
      }
    return Process(
      pid: pid, parent: info.kp_eproc.e_ppid, path: path, arguments: arguments(pid))
  }

  /// argv via KERN_PROCARGS2: int32 argc, exec path, NUL padding, argv.
  private static func arguments(_ pid: pid_t) -> [String] {
    var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
    var size = 0
    guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > 4 else { return [] }
    var buffer = [UInt8](repeating: 0, count: size)
    guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0 else { return [] }

    let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
    var index = 4
    while index < size, buffer[index] != 0 { index += 1 }  // exec path
    while index < size, buffer[index] == 0 { index += 1 }  // padding
    var arguments: [String] = []
    while arguments.count < argc, index < size {
      let start = index
      while index < size, buffer[index] != 0 { index += 1 }
      arguments.append(String(decoding: buffer[start..<index], as: UTF8.self))
      index += 1
    }
    return arguments
  }
}

/// Append-only record of every request that needed Touch ID.
enum AuditLog {
  static var url: URL {
    if ProcessInfo.processInfo.environment["KEYFOB_HOME"] != nil {
      return Paths.home.appendingPathComponent("audit.log")
    }
    return URL(fileURLWithPath: NSHomeDirectory())
      .appendingPathComponent("Library/Logs/keyfob.log")
  }

  static func record(_ action: String, caller: Caller, outcome: String) {
    let timestamp = ISO8601DateFormatter().string(from: Date())
    let origin = caller.origin.map { " \($0)" } ?? ""
    let line =
      "\(timestamp) \(outcome) \(Caller.clean(action.split(separator: "\n").joined(separator: " "), limit: 200))\(origin) [\(caller.detail)]\n"
    let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
    guard fd >= 0 else { return }
    defer { close(fd) }
    _ = line.utf8CString.withUnsafeBufferPointer { write(fd, $0.baseAddress, $0.count - 1) }
  }

  static func show(lines: Int) throws {
    guard Paths.exists(url) else { return }
    let text = try String(contentsOf: url, encoding: .utf8)
    print(text.split(separator: "\n").suffix(lines).joined(separator: "\n"))
  }
}

extension Caller {
  /// First line of the commit or tag being signed. git hands ssh-keygen the
  /// object in a temp file (its last argument): headers, blank line, message.
  var signedSubject: String? {
    guard let file = chain.first(where: { $0.name == "ssh-keygen" })?.arguments.last,
      let handle = FileHandle(forReadingAtPath: file),
      let data = try? handle.read(upToCount: 64 * 1024)
    else { return nil }
    let text = String(decoding: data, as: UTF8.self)
    guard let body = text.range(of: "\n\n") else { return nil }
    var subject = String(text[body.upperBound...].prefix { $0 != "\n" })
    while subject.hasSuffix(".") { subject.removeLast() }
    if subject.count > 50 { subject = subject.prefix(49) + "…" }
    return subject.isEmpty ? nil : subject
  }
}
