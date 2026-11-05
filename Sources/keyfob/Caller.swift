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

  /// Two lines for the Touch ID sheet, which renders as
  /// "keyfob is trying to <action>\n<origin>."
  func reason(_ action: String) -> String {
    guard let origin else { return Caller.clean(action) }
    return Caller.clean(action) + "\n" + Caller.clean(origin)
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
  /// shell, wrapper or helper.
  var initiator: Process? {
    chain.first { !Caller.isPlumbing($0) && Caller.agentName($0) == nil }
  }

  /// Where it ran: a coding agent if one is in the chain, else the app bundle
  /// (iTerm, Visual Studio Code, …) the chain descends from.
  var app: String? {
    chain.lazy.compactMap(Caller.agentName).first
      ?? chain.lazy.compactMap(Caller.bundleName).first
  }

  /// Repository the git operation runs in (git chdirs to the work tree).
  var repository: String? {
    chain.first { $0.name.hasPrefix("git") }?.workingDirectory
      .map { URL(fileURLWithPath: $0).lastPathComponent }
  }

  var gitSubcommand: String? {
    chain.lazy.compactMap(\.gitSubcommand).first { !$0.hasPrefix("credential") }
  }

  /// `github.com` from `ssh -o … git@github.com git-upload-pack '…'`
  var sshHost: String? {
    let options: Set<String> = [
      "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O",
      "-o", "-P", "-p", "-Q", "-R", "-S", "-W", "-w",
    ]
    guard let destination = chain.first(where: { $0.name == "ssh" })?
      .firstOperand(optionsWithValues: options)
    else { return nil }
    let host = destination.split(separator: "@").last.map(String.init) ?? destination
    return host.hasPrefix("ssh://") ? String(host.dropFirst(6)) : host
  }

  /// File named last on the initiator's command line (`sops -d secrets.yaml`).
  var targetFile: String? {
    guard let last = initiator?.arguments.dropFirst().last, !last.hasPrefix("-") else {
      return nil
    }
    return URL(fileURLWithPath: last).lastPathComponent
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

  private static let agents = [
    "claude": "Claude Code", "codex": "Codex", "gemini": "Gemini CLI",
    "cursor-agent": "Cursor Agent", "opencode": "opencode", "aider": "aider",
  ]

  private static func agentName(_ process: Process) -> String? {
    agents[process.name]
  }

  /// Outermost .app in the executable path, so helpers map to their product.
  private static func bundleName(_ process: Process) -> String? {
    guard let range = process.path.range(of: ".app/") else { return nil }
    return URL(fileURLWithPath: String(process.path[..<range.lowerBound])).lastPathComponent
  }

  private static func label(_ process: Process) -> String {
    process.gitSubcommand.map { "git \($0)" } ?? process.name
  }

  private static let plumbing: Set<String> = [
    "keyfob", "git-credential-keyfob", "age-plugin-se", "xcrun", "ssh", "ssh-keygen",
    "timeout", "env", "nice", "sh", "bash", "zsh", "dash", "fish", "login",
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
      "\(timestamp) \(outcome) \(Caller.clean(action, limit: 200))\(origin) [\(caller.detail)]\n"
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
