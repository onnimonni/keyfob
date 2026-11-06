# keyfob

Secure Enclave keys for SSH, git and age on macOS, unlocked with Touch ID.

One binary that replaces [Secretive](https://github.com/maxgoedjen/secretive),
[age-plugin-se](https://github.com/remko/age-plugin-se) and the
`git-credential-osxkeychain` password prompts:

- **SSH agent**: named P-256 keys in the Secure Enclave
- **git commit/tag signing**: SSH-format signatures through the agent
- **age plugin**: runs as `age-plugin-se`, so existing `age1se1…` recipients and
  `AGE-PLUGIN-SE-…` identities (and sops files) keep working
- **git credential helper**: tokens are encrypted to a Secure Enclave key; storing
  needs no prompt, reading needs Touch ID

Private keys never leave the Secure Enclave. The files in `~/.config/keyfob` are
wrapped handles that only work on the Mac that created them. No Apple Developer
signing or entitlements are needed (CryptoKit's `SecureEnclave` API).

Requires macOS 26 and a Mac with Touch ID (or a Magic Keyboard with Touch ID).

## Keys

`keyfob init` creates a `default` SSH key, a `default` age key and the git
credentials key. Add more with `keyfob new ssh|age NAME [--dangerous]`:

| | normal | `--dangerous` |
|---|---|---|
| Unlock | Touch ID or password | Touch ID only |
| Approvals remembered | yes, see below | never: every use asks |
| Fingerprints change | key keeps working | key is destroyed |
| Touch ID sheet | names the key unless it is `default` | 🚨 names the key, right under the title |

The git credentials key is Touch ID only and survives fingerprint changes.

Pick SSH keys per host in `~/.ssh/config`; the agent offers all of them:

```
Host prod-*
  IdentityFile ~/.config/keyfob/ssh/prod.pub
  IdentitiesOnly yes
```

Decrypt with a named age key: `age -d -i ~/.config/keyfob/age/prod.txt`.

## Remembered approvals

The agent is the one place that unlocks keys: SSH signing, and also git
credentials and age decryption, which the credential helper and age plugin
send to it (they ask Touch ID themselves only when no agent runs). It may
remember one approval for a few minutes, but only for the same scope:

| Request | Remembered | Scope |
|---|---|---|
| commit signing (verified commits only) | 5 min | app process + session + code identity + key + repository |
| SSH login, fetch | 5 min | … + user + host key of the bound session |
| HTTPS fetch, pull, clone | 5 min | … + host + username |
| age / sops decrypt | 2 min | … + age identity + project directory |
| any push, tags, unverified or other signatures | never | |
| requests forwarded with `ssh -A`, unknown apps, dangerous keys | never | |

- **Session**: the coding agent process (one `claude` session), else the
  terminal tab's `login`, else the outermost shell the app started. A script in
  another tab is another session.
- **Code identity**: the app's signing team ID, or its cdhash when ad-hoc
  signed (e.g. installed with nix); code that fails validation is never
  remembered.
- A remembered approval ends after its time, when the screen locks, when the
  Mac sleeps, or with `keyfob lock`. `keyfob status` lists the active ones.
- The Touch ID sheet says so: its last line reads `⏱️ remembered for 5 min`.

## Threat model

keyfob guards against a key being used without you noticing: by a remote host
you reached with `ssh -A`, by an app or script that runs a command you did not
mean to approve, or by someone with the key files but not your Mac. The private
keys never leave the Secure Enclave, and every first use needs Touch ID (or
your password, for normal keys).

It does **not** defend against malware already running as your user. Such a
program can read the key handles in `~/.config/keyfob` and ask the Secure
Enclave itself, edit key metadata, replace the app-named copies in
`~/.config/keyfob/bin`, or pose as another app on the Touch ID sheet. macOS
offers no boundary between programs of the same user that an unsigned command
line tool could use. The Touch ID sheet and the audit log are context for you,
not proof of who asked.

Within that model the agent:
- reuses an approval only in its scope (see Remembered approvals); a git
  signature counts as a commit only after its content was checked against the
  hash being signed, and an SSH login only for the host key ssh actually
  reached in that session;
- never reuses one for pushes, FORCE pushes, tags, forwarded requests or
  unknown apps;
- decrypts git credentials itself and returns only plaintext that
  authenticates against the requested host;
- answers forwarded agents (`ssh -A`) only with SSH signatures, each asked
  for, never with decryption, `lock` or `status`.

## Install

Requires macOS 26 and a Mac with Touch ID (or a Magic Keyboard with Touch ID).
Every install gives three commands (`keyfob`, `git-credential-keyfob`,
`age-plugin-se`) and the sudo module `lib/pam/pam_keyfob.so`. Then, once per
Mac and user:

```sh
keyfob init                   # 'default' SSH and age keys, git credentials key
```

and add `~/.config/keyfob/ssh/default.pub` to GitHub twice: as an
authentication key and as a signing key.

### nix-darwin + home-manager

```nix
# flake.nix
inputs.keyfob = {
  url = "github:onnimonni/keyfob";
  inputs.nixpkgs.follows = "nixpkgs";
};

# nix-darwin: package and sudo
imports = [ inputs.keyfob.darwinModules.default ];
programs.keyfob = {
  enable = true;
  sudo = true;   # sudo Touch ID sheet names the command (see "sudo")
};

# home-manager: per-user agent and config
home-manager.users.me = {
  imports = [ inputs.keyfob.homeManagerModules.default ];
  programs.keyfob = {
    enable = true;
    # sshAgent = true;   # launchd agent + SSH_AUTH_SOCK (default)
    # sshConfig = true;  # Include in ~/.ssh/config (default: programs.ssh.enable)
    # git = true;        # signing + credential helper (default: programs.git.enable)
    # sops = true;       # SOPS_AGE_KEY_FILE = the 'default' age key
  };
};
```

home-manager alone (no nix-darwin) works the same; only `sudo` needs
nix-darwin. Without either: `nix profile install github:onnimonni/keyfob`.

`age-plugin-se` is part of keyfob: remove the separate `age-plugin-se` package.

### Homebrew

```sh
brew tap onnimonni/keyfob https://github.com/onnimonni/keyfob
brew install keyfob           # builds from source with the Command Line Tools
brew services start keyfob    # the agent, at login
keyfob install-ssh-config     # plain `ssh` uses the agent
git config --global include.path ~/.config/keyfob/gitconfig
```

For sudo, copy the module somewhere only root can write: sudo runs it as
root, and `/opt/homebrew` is writable by your user, so loading it from there
would let any program you run replace code that runs as root. Repeat after
upgrades:

```sh
sudo install -d -o root -g wheel -m 755 /usr/local/lib/pam
sudo install -o root -g wheel -m 444 "$(brew --prefix keyfob)/lib/pam/pam_keyfob.so" /usr/local/lib/pam/
```

then add `auth sufficient /usr/local/lib/pam/pam_keyfob.so` to the top of
`/etc/pam.d/sudo_local`.
It conflicts with Homebrew's `age-plugin-se` formula, which keyfob replaces.

### make (manual)

```sh
make && sudo make install          # /usr/local/bin, /usr/local/lib/pam
make install PREFIX=$HOME/.local   # without sudo
keyfob install-launch-agent        # the agent, at login
keyfob install-ssh-config
git config --global include.path ~/.config/keyfob/gitconfig
```

`sudo make uninstall` removes it again (keys in `~/.config/keyfob` stay).

### MDM / installer package

```sh
make pkg                                                  # unsigned
make pkg PKG_SIGN="Developer ID Installer: Org (TEAMID)"  # signed, for MDM
```

builds `.build/keyfob-VERSION.pkg`, installing into `/usr/local`. Pair it with
a login script running `keyfob install-launch-agent`, `keyfob
install-ssh-config` and the git include for each user, and ship
`/etc/pam.d/sudo_local` with the pam_keyfob line from your MDM. Users run
`keyfob init` themselves: the keys are created in their Mac's Secure Enclave
and never leave it. (Built from a shell that marks files with
`com.apple.provenance`, the payload lists harmless `._` entries.)

### What `install-ssh-config` does

It puts `Include ~/.config/keyfob/ssh_config` at the top of `~/.ssh/config`
(so its `IdentityAgent` wins over later ones), once, keeping a backup. It
refuses a symlinked config (nix, dotfiles): add the line there, or use the
home-manager `sshConfig` option.

## Usage

```
keyfob init                           create the 'default' keys and config snippets
keyfob new ssh|age NAME [--dangerous] create another key
keyfob delete ssh|age NAME            delete a key (it is gone for good)
keyfob list                           show keys and public keys
keyfob status                         show approvals the agent still remembers
keyfob lock                           forget all approvals now
keyfob ssh-pubkey [NAME]              print an SSH public key
keyfob age-recipient [NAME]           print an age recipient (age1se1...)
keyfob ssh-agent [--socket PATH]      run the agent in the foreground
keyfob install-ssh-config             use the agent from ~/.ssh/config
keyfob install-launch-agent           start the agent at login (LaunchAgent)
keyfob env                            print SSH_AUTH_SOCK and SOPS_AGE_KEY_FILE exports
keyfob log                            show recent Touch ID requests and who made them
keyfob git-credential get|store|erase
```

## The Touch ID sheet

Each sheet is titled with the requesting app (`claude`, `codex`, `iTerm`, …, or
`unknown`) and lists what is being unlocked:

```
claude is trying to sign a Git commit:
📝 Add login rate limiting
📁 ~/Projects/demo-repo
📦 github.com:onnimonni/demo-repo.

iTerm is trying to FORCE push:
🚨 using dangerous 'prod' key
🌐 github.com
📦 org/repo
📁 ~/Projects/repo
🌿 main
‼️ may rewrite history.

claude is trying to git fetch:
🌐 github.com
📦 org/repo
📁 ~/Projects/repo.

iTerm is trying to decrypt a file using age:
📄 secrets/secrets.yaml
📁 ~/.dotfiles
🔧 sops.
```

Requests forwarded from another machine (`ssh -A`) are detected from ssh's
`session-bind@openssh.com` notice, and from anything other than a login
reaching the agent through the local ssh client. Their sheet shows only what
is asked and `🔀 forwarded from <host>`, and they always ask again.

macOS titles the sheet with the executable's file name, so keyfob runs a copy of
itself named after the app (`~/.config/keyfob/bin/<app>`). That title is
cosmetic: any program can name its executable anything. The real story is in
`~/Library/Logs/keyfob.log`, which records each request, its outcome (`allowed`,
`reused`, `denied`) and the full process chain (pids and command lines).

## sudo

`lib/pam/pam_keyfob.so` (in the nix package; `.build/release/libpam_keyfob.dylib`
from `swift build`) replaces the generic "sudo is trying to execute a command as
administrator" with what runs, where, and who asked:

```
sudo is trying to run as root:
🔧 brew install foo
📁 ~/Projects
🤖 requested by claude.
```

sudo runs the module as root, so it must live where only root can write, along
the whole path (the nix store, or `/usr/local/lib/pam` installed with `sudo`),
never in a directory your user owns such as `/opt/homebrew`.

Add it as `sufficient` at the top of `/etc/pam.d/sudo_local`, so denying,
cancelling or any error falls through to the next line and sudo keeps working:

```
auth       sufficient     /path/to/pam_keyfob.so
auth       sufficient     pam_tid.so
```

With nix-darwin, `programs.keyfob.sudo = true;` from `darwinModules.default`
(see Install) does this, keeping `pam_reattach` first when enabled.

Each approval or denial is appended to `~/Library/Logs/keyfob.log`. The sheet
title stays "sudo": sudo is what asks. `sudo -A` (askpass) is left to the next
module.

## Files

`~/.config/keyfob` (`$KEYFOB_HOME` overrides):

| File | |
|---|---|
| `ssh/NAME.key`, `ssh/NAME.pub` | SSH key handle and public key |
| `age/NAME.txt` | age identity (age-plugin-se format) |
| `*/NAME.json` | key protection |
| `credentials.key`, `credentials.protection` | key that git credentials are encrypted to |
| `credentials/` | encrypted git credentials, one file per host |
| `gitconfig` | include: signing with `ssh/default.pub`, credential helper |
| `ssh_config` | include setting `IdentityAgent` |
| `allowed_signers` | all SSH keys, for `git verify-commit` |
| `bin/` | copies of keyfob named after apps (see above) |

Add `ssh/default.pub` to GitHub twice: as an authentication key and as a
signing key. Move an existing token into keyfob with:

```sh
printf 'protocol=https\nhost=github.com\nusername=you\npassword=TOKEN\n' | git credential-keyfob store
```

## Development

```sh
swift build -c release
./scripts/e2e-test.sh          # keys without Touch ID; needs a Secure Enclave
./scripts/forwarding-test.sh   # ssh -A against Linux sshd containers (Apple `container`)
nix build
```

## Credits

Age plugin code in `Sources/keyfob/Age` comes from
[age-plugin-se](https://github.com/remko/age-plugin-se) by Remko Tronçon (MIT,
see `Sources/keyfob/Age/LICENSE-age-plugin-se.txt`). Ideas from
[sod](https://github.com/botanica-consulting/sod) and
[se-agent](https://github.com/nhz-io/se-agent).
