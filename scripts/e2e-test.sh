#!/usr/bin/env bash
# End-to-end test with keys that skip Touch ID (Secure Enclave still required).
set -euo pipefail

BIN=${1:-$(swift build -c release --show-bin-path)/keyfob}
WORK=$(mktemp -d)
SOCK=/tmp/keyfob-test-$$.sock
trap 'kill "${AGENT:-}" 2>/dev/null || true; rm -rf "$WORK" "$SOCK"' EXIT

mkdir "$WORK/bin"
for name in keyfob git-credential-keyfob age-plugin-se; do ln -s "$BIN" "$WORK/bin/$name"; done
export PATH="$WORK/bin:$PATH" KEYFOB_HOME="$WORK/home" SSH_AUTH_SOCK="$SOCK" KEYFOB_AGENT_SOCKET="$SOCK"

keyfob init --insecure-no-touch-id >/dev/null
keyfob new ssh second --insecure-no-touch-id >/dev/null
keyfob new age second --insecure-no-touch-id >/dev/null

echo "ssh agent offers every key"
keyfob ssh-agent --socket "$SOCK" 2>"$WORK/agent.log" &
AGENT=$!
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ "$(ssh-add -L | cut -d' ' -f3)" = "$(printf 'default\nsecond')" ]

echo "git signing with the default key, twice (second reuses the approval)"
git init -q "$WORK/repo"
git -C "$WORK/repo" config include.path "$KEYFOB_HOME/gitconfig"
for message in one two; do
  git -C "$WORK/repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "$message"
done
git -C "$WORK/repo" verify-commit HEAD 2>&1 | grep -q 'Good "git" signature'
grep -q '^.* reused sign a Git commit' "$KEYFOB_HOME/audit.log"

echo "signing with a named key"
echo hello >"$WORK/msg"
ssh-keygen -Y sign -n file -f "$KEYFOB_HOME/ssh/second.pub" "$WORK/msg" 2>/dev/null
ssh-keygen -Y verify -n file -f "$KEYFOB_HOME/allowed_signers" -I '*' -s "$WORK/msg.sig" <"$WORK/msg" >/dev/null

echo "age with each key"
for name in default second; do
  [ "$(echo "secret $name" | age -r "$(keyfob age-recipient "$name")" | age -d -i "$KEYFOB_HOME/age/$name.txt")" = "secret $name" ]
done

echo "git credentials"
printf 'protocol=https\nhost=example.com\nusername=bob\npassword=tok\n' | git credential-keyfob store
[ "$(printf 'protocol=https\nhost=example.com\n' | git credential-keyfob get)" = "$(printf 'username=bob\npassword=tok')" ]
[ -z "$(printf 'protocol=https\nhost=example.com\nusername=eve\n' | git credential-keyfob get)" ]
# erasing eve's credential leaves bob's alone
printf 'protocol=https\nhost=example.com\nusername=eve\n' | git credential-keyfob erase
[ -n "$(printf 'protocol=https\nhost=example.com\n' | git credential-keyfob get)" ]
printf 'protocol=https\nhost=example.com\n' | git credential-keyfob erase
[ -z "$(printf 'protocol=https\nhost=example.com\n' | git credential-keyfob get)" ]


echo "approvals: git credentials and age reuse through the agent"
printf 'protocol=https\nhost=example.com\nusername=bob\npassword=tok\n' | git credential-keyfob store
for _ in 1 2; do printf 'protocol=https\nhost=example.com\n' | git credential-keyfob get >/dev/null; done
grep -q ' reused git credential\| reused use Git credentials' "$KEYFOB_HOME/audit.log"
echo "secret" | age -r "$(keyfob age-recipient)" -o "$WORK/secret.age"
for _ in 1 2; do age -d -i "$KEYFOB_HOME/age/default.txt" "$WORK/secret.age" >/dev/null; done
grep -q ' reused decrypt a file using age' "$KEYFOB_HOME/audit.log"

echo "status and lock"
keyfob status | grep -q 'commits in'
keyfob lock >/dev/null
[ "$(keyfob status)" = "no remembered approvals" ]
git -C "$WORK/repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m after-lock
[ "$(grep 'sign a Git commit' "$KEYFOB_HOME/audit.log" | tail -1 | cut -d' ' -f2)" = allowed ]

echo "install-ssh-config"
mkdir -p "$WORK/fakehome/.ssh"
printf 'Host *\n  IdentityAgent /somewhere/else\n' >"$WORK/fakehome/.ssh/config"
HOME="$WORK/fakehome" keyfob install-ssh-config >/dev/null
HOME="$WORK/fakehome" keyfob install-ssh-config >/dev/null
[ "$(grep -c "^Include $KEYFOB_HOME/ssh_config" "$WORK/fakehome/.ssh/config")" = 1 ]
[ "$(sed -n 2p "$WORK/fakehome/.ssh/config")" = "Include $KEYFOB_HOME/ssh_config" ]
[ -f "$WORK/fakehome/.ssh/config.keyfob-backup" ]

echo "ok"
