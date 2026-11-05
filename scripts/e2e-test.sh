#!/usr/bin/env bash
# End-to-end test with keys that skip Touch ID (Secure Enclave still required).
set -euo pipefail

BIN=${1:-$(swift build -c release --show-bin-path)/keyfob}
WORK=$(mktemp -d)
SOCK=/tmp/keyfob-test-$$.sock
trap 'kill "${AGENT:-}" 2>/dev/null || true; rm -rf "$WORK" "$SOCK"' EXIT

mkdir "$WORK/bin"
for name in keyfob git-credential-keyfob age-plugin-se; do ln -s "$BIN" "$WORK/bin/$name"; done
export PATH="$WORK/bin:$PATH" KEYFOB_HOME="$WORK/home" SSH_AUTH_SOCK="$SOCK"

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

echo "ok"
