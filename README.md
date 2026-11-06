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
| commit signing | 5 min | app process + session + code identity + key + repository |
| SSH login, normal push, fetch | 5 min | … + `user@host:port` |
| HTTPS fetch, pull, normal push | 5 min | … + host + username |
| age / sops decrypt | 2 min | … + age identity + project directory |
| FORCE push or branch delete, tags, other signatures | never | |
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

## Install

### Nix + home-manager

```nix
# flake.nix
inputs.keyfob.url = "github:onnimonni/keyfob";

# home-manager config
imports = [ inputs.keyfob.homeManagerModules.default ];
programs.keyfob = {
  enable = true;
  # sshAgent = true;   # launchd agent + SSH_AUTH_SOCK (default)
  # sshConfig = true;  # Include in ~/.ssh/config (default: programs.ssh.enable)
  # git = true;        # include signing + credential config (default: programs.git.enable)
  # sops = true;       # SOPS_AGE_KEY_FILE = the 'default' age key
};
```

Then once per Mac:

```sh
keyfob init
```

### Without nix

```sh
swift build -c release
install -m755 .build/release/keyfob /usr/local/bin/keyfob
ln -s keyfob /usr/local/bin/git-credential-keyfob
ln -s keyfob /usr/local/bin/age-plugin-se
keyfob init                   # keys and config snippets
keyfob install-launch-agent   # agent at login
keyfob install-ssh-config     # plain `ssh` uses the agent
```

`keyfob install-ssh-config` puts `Include ~/.config/keyfob/ssh_config` at the
top of `~/.ssh/config` (so its `IdentityAgent` wins over later ones), once,
keeping a backup. It refuses a symlinked config (nix, dotfiles): add the line
there, or use the home-manager `sshConfig` option.

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
