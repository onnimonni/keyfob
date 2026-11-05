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
| SSH agent | one approval covers 5 minutes per app and key | every use |
| Fingerprints change | key keeps working | key is destroyed |
| Touch ID sheet | names the key unless it is `default` | 🚨 names the key |

The git credentials key is Touch ID only and survives fingerprint changes.

Pick SSH keys per host in `~/.ssh/config`; the agent offers all of them:

```
Host prod-*
  IdentityFile ~/.config/keyfob/ssh/prod.pub
  IdentitiesOnly yes
```

Decrypt with a named age key: `age -d -i ~/.config/keyfob/age/prod.txt`.

## Install

### Nix + home-manager

```nix
# flake.nix
inputs.keyfob.url = "github:onnimonni/keyfob";

# home-manager config
imports = [ inputs.keyfob.homeManagerModules.default ];
programs.keyfob = {
  enable = true;
  # sshAgent = true;  # launchd agent + SSH_AUTH_SOCK (default)
  # git = true;       # include signing + credential config (default: programs.git.enable)
  # sops = true;      # SOPS_AGE_KEY_FILE = the 'default' age key
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
keyfob init   # prints the remaining setup steps
```

## Usage

```
keyfob init                           create the 'default' keys and config snippets
keyfob new ssh|age NAME [--dangerous] create another key
keyfob delete ssh|age NAME            delete a key (it is gone for good)
keyfob list                           show keys and public keys
keyfob ssh-pubkey [NAME]              print an SSH public key
keyfob age-recipient [NAME]           print an age recipient (age1se1...)
keyfob ssh-agent [--socket PATH]      run the SSH agent in the foreground
keyfob env                            print SSH_AUTH_SOCK and SOPS_AGE_KEY_FILE exports
keyfob log                            show recent Touch ID requests and who made them
keyfob install-launch-agent           write a LaunchAgent that runs the SSH agent
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

iTerm is trying to git push over SSH:
📦 github.com:org/repo
📁 ~/Projects/repo
🚨 using your dangerous 'prod' SSH key.

claude is trying to git fetch over HTTPS:
📦 github.com/org/repo
📁 ~/Projects/repo.

iTerm is trying to decrypt a file using age:
📄 secrets/secrets.yaml
📁 ~/.dotfiles
🔧 sops.
```

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
| `credentials.key` | key that git credentials are encrypted to |
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
./scripts/e2e-test.sh   # uses keys without Touch ID, needs a Secure Enclave
nix build
```

## Credits

Age plugin code in `Sources/keyfob/Age` comes from
[age-plugin-se](https://github.com/remko/age-plugin-se) by Remko Tronçon (MIT,
see `Sources/keyfob/Age/LICENSE-age-plugin-se.txt`). Ideas from
[sod](https://github.com/botanica-consulting/sod) and
[se-agent](https://github.com/nhz-io/se-agent).
