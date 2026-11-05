# keyfob

Secure Enclave keys for SSH, git and age on macOS. Every use needs Touch ID.

One binary that replaces [Secretive](https://github.com/maxgoedjen/secretive),
[age-plugin-se](https://github.com/remko/age-plugin-se) and the
`git-credential-osxkeychain` password prompts:

- **SSH agent**: P-256 key in the Secure Enclave, Touch ID per signature
- **git commit/tag signing**: SSH-format signatures through the agent
- **age plugin**: runs as `age-plugin-se`, so existing `age1se1…` recipients and
  `AGE-PLUGIN-SE-…` identities (and sops files) keep working
- **git credential helper**: tokens are encrypted to a Secure Enclave key; storing
  needs no prompt, reading needs Touch ID

Private keys never leave the Secure Enclave. The files in `~/.config/keyfob` are
wrapped handles that only work on the Mac that created them. No Apple Developer
signing or entitlements are needed (CryptoKit's `SecureEnclave` API).

Requires macOS 26 and a Mac with Touch ID (or a Magic Keyboard with Touch ID).
Keys use `biometryAny`: there is no password fallback, and enrolling new
fingers does not invalidate them.

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
  # sops = true;      # SOPS_AGE_KEY_FILE
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
keyfob init                       create missing keys and config snippets
keyfob status                     show public keys
keyfob ssh-agent [--socket PATH]  run the SSH agent in the foreground
keyfob ssh-pubkey                 print the SSH public key
keyfob age-recipient              print the age recipient (age1se1...)
keyfob env                        print SSH_AUTH_SOCK and SOPS_AGE_KEY_FILE exports
keyfob log                        show recent Touch ID requests and who made them
keyfob install-launch-agent       write a LaunchAgent that runs the SSH agent
keyfob git-credential get|store|erase
```

Every Touch ID sheet is titled with the requesting app and says what is being
unlocked:

```
Claude Code is trying to sign a Git commit:
'Add login rate limiting'
in:
'~/Projects/demo-repo'.

iTerm is trying to log in over SSH to:
'git@github.com:22'
for:
'/org/repo.git'
via git push.

Claude Code is trying to decrypt with age:
'~/.dotfiles/secrets/secrets.yaml'
via sops.
```

macOS titles the sheet with the executable's file name, so keyfob runs a copy of
itself named after the app (`~/.config/keyfob/bin/<App>`). That title is
cosmetic: any program can name its executable anything. The real story is in
`~/Library/Logs/keyfob.log`, which records each request, its outcome and the
full process chain (pids and command lines).

`keyfob init` writes into `~/.config/keyfob` (`$KEYFOB_HOME` overrides):

| File | |
|---|---|
| `ssh.key`, `ssh.pub` | SSH signing key handle and public key |
| `age.txt` | age identity (age-plugin-se format) |
| `credentials.key` | key that git credentials are encrypted to |
| `credentials/` | encrypted git credentials, one file per host |
| `gitconfig` | include for signing + credential helper |
| `ssh_config` | include setting `IdentityAgent` |
| `allowed_signers` | for `git verify-commit` |

Add the `ssh.pub` key to GitHub twice: as an authentication key and as a
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
