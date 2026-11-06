#!/usr/bin/env bash
# SSH agent-forwarding detection, end to end against Linux sshd containers.
#
# Uses Apple's `container` CLI (no docker). Containers get an IP on the default
# 192.168.64.0/24 network that both the host and other containers can reach, so
# nothing is published. Keys skip Touch ID (Secure Enclave still required) and
# live in a throwaway KEYFOB_HOME; ~/.config/keyfob and ~/.ssh are not touched.
#
#   scripts/forwarding-test.sh [path/to/keyfob]
#
# KEYFOB_FWD_REBUILD=1 rebuilds the sshd images; KEYFOB_FWD_KEEP=1 keeps the
# containers running after the test.
set -euo pipefail

BIN=${1:-$(cd "$(dirname "$0")/.." && pwd)/.build/release/keyfob}
WORK=$(mktemp -d)
SOCK=/tmp/kf-fwd-$$.sock
IMG_NEW=kf-sshd-new:test # alpine: OpenSSH 9.x, sends session-bind@openssh.com
IMG_OLD=kf-sshd-old:test # ubuntu 20.04: OpenSSH 8.2, predates session-bind
CONTAINERS=()
FAILED=0

cleanup() {
  kill "${AGENT:-}" 2>/dev/null || true
  if [ -z "${KEYFOB_FWD_KEEP:-}" ]; then
    for c in ${CONTAINERS[@]+"${CONTAINERS[@]}"}; do
      container delete --force "$c" >/dev/null 2>&1 || true
    done
  fi
  rm -rf "$WORK" "$SOCK"
}
trap cleanup EXIT

mkdir "$WORK/bin"
for name in keyfob git-credential-keyfob age-plugin-se; do ln -s "$BIN" "$WORK/bin/$name"; done
export PATH="$WORK/bin:$PATH" KEYFOB_HOME="$WORK/home" SSH_AUTH_SOCK="$SOCK"
AUDIT="$KEYFOB_HOME/audit.log"

# ---------------------------------------------------------------- helpers
pass() { echo "PASS $1"; }
fail() {
  echo "FAIL $1"
  FAILED=1
}
# Audit lines appended since the given line count.
mark() { [ -f "$AUDIT" ] && echo $(($(wc -l <"$AUDIT"))) || echo 0; }
since() { [ -f "$AUDIT" ] && tail -n "+$(($1 + 1))" "$AUDIT" || true; }
count() { printf '%s' "$1" | grep -c '' || true; }
show() { printf '%s\n' "$1" | sed 's/^/    /'; }

# Every line in $2 matches each pattern in $3…; exactly $1 lines.
expect() {
  local n=$1 lines=$2 pattern
  shift 2
  [ "$(count "$lines")" -eq "$n" ] || return 1
  for pattern in "$@"; do
    [ "$(printf '%s' "$lines" | grep -c -- "$pattern" || true)" -eq "$n" ] || return 1
  done
}
never() { ! printf '%s' "$1" | grep -q -- "$2"; }

ip_of() { container inspect "$1" | jq -r '.[0].status.networks[0].ipv4Address' | cut -d/ -f1; }

# Start an sshd container; sets IP once port 22 answers. Not run in a
# subshell, so the cleanup list sees the container.
start_sshd() {
  local name=$1 image=$2
  container delete --force "$name" >/dev/null 2>&1 || true
  CONTAINERS+=("$name")
  container run -d --name "$name" -e "AUTHORIZED_KEYS=$PUBKEY" "$image" >/dev/null 2>&1
  IP=$(ip_of "$name")
  for _ in $(seq 100); do
    (exec 3<>"/dev/tcp/$IP/22") 2>/dev/null && break
    sleep 0.2
  done
}

# ssh without the user's config or known_hosts, through the test agent only.
SSH_OPTS=(-F /dev/null -o StrictHostKeyChecking=no -o "UserKnownHostsFile=$WORK/known_hosts"
  -o IdentitiesOnly=no -o LogLevel=ERROR -o ConnectTimeout=10)
REMOTE_SSH_OPTS='-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR'
remote() { ssh "${SSH_OPTS[@]}" "$@"; }

# ---------------------------------------------------------------- images
build_images() {
  local dir=$WORK/images
  mkdir -p "$dir/new" "$dir/old"
  cat >"$dir/entrypoint.sh" <<'EOF'
#!/bin/sh
# Writes the authorized key handed in by env, then runs sshd in the foreground.
set -e
mkdir -p /root/.ssh /run/sshd
printf '%s\n' "$AUTHORIZED_KEYS" >/root/.ssh/authorized_keys
cp /root/.ssh/authorized_keys /root/key.pub
chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
ssh-keygen -A >/dev/null
exec /usr/sbin/sshd -D -e
EOF
  chmod +x "$dir/entrypoint.sh"
  cp "$dir/entrypoint.sh" "$dir/new/" && cp "$dir/entrypoint.sh" "$dir/old/"
  cat >"$dir/new/Dockerfile" <<'EOF'
FROM docker.io/library/alpine:3.20
RUN apk add --no-cache openssh git \
 && sed -i 's/^root:[!*]*:/root:*:/' /etc/shadow \
 && printf 'PermitRootLogin prohibit-password\nPubkeyAuthentication yes\nAllowAgentForwarding yes\nLogLevel VERBOSE\n' >/etc/ssh/sshd_config.d/kf.conf
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
EOF
  cat >"$dir/old/Dockerfile" <<'EOF'
FROM docker.io/library/ubuntu:20.04
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server openssh-client git ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && printf 'PermitRootLogin prohibit-password\nPubkeyAuthentication yes\nAllowAgentForwarding yes\nLogLevel VERBOSE\n' >>/etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
EOF
  for pair in "new:$IMG_NEW" "old:$IMG_OLD"; do
    local sub=${pair%%:*} image=${pair#*:}
    if [ -n "${KEYFOB_FWD_REBUILD:-}" ] || ! container image inspect "$image" >/dev/null 2>&1; then
      echo "building $image"
      # -q hangs in container 1.5; plain progress into a log instead
      container build --progress plain -t "$image" -f "$dir/$sub/Dockerfile" "$dir/$sub" \
        >"$WORK/build-$sub.log" 2>&1 || { cat "$WORK/build-$sub.log"; exit 2; }
    fi
  done
}

# ---------------------------------------------------------------- setup
command -v container >/dev/null || { echo "needs Apple's container CLI"; exit 2; }
container system status >/dev/null 2>&1 || { echo "run: container system start"; exit 2; }
command -v jq >/dev/null || { echo "needs jq"; exit 2; }

keyfob init --insecure-no-touch-id >/dev/null
PUBKEY=$(cat "$KEYFOB_HOME/ssh/default.pub")
KEYBLOB=$(cut -d" " -f1,2 "$KEYFOB_HOME/ssh/default.pub") # ssh-add -L shows the key name, not the .pub comment

build_images

keyfob ssh-agent --socket "$SOCK" 2>"$WORK/agent.log" &
AGENT=$!
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "agent did not start"; cat "$WORK/agent.log"; exit 2; }

start_sshd kf-fwd-a "$IMG_NEW"; A=$IP
start_sshd kf-fwd-b "$IMG_NEW"; B=$IP
echo "A=$A (new OpenSSH)  B=$B"

# ---------------------------------------------------------------- scenarios
echo "1. direct login to A: allowed, not forwarded"
m=$(mark)
remote "root@$A" true
lines=$(since "$m")
if expect 1 "$lines" ' allowed log in over SSH' && never "$lines" forwarded; then
  pass "1 direct login"
else fail "1 direct login"; fi
show "$lines"

echo "2. ssh -A to A, ssh-add -L and ssh-keygen -Y sign twice inside: forwarded, never reused"
m=$(mark)
out=$(remote -A "root@$A" "ssh-add -L && echo one >/root/m1 && echo two >/root/m2 \
  && ssh-keygen -q -Y sign -n git -f /root/key.pub /root/m1 \
  && ssh-keygen -q -Y sign -n git -f /root/key.pub /root/m2 && echo signed")
lines=$(since "$m")
fwd=$(printf '%s' "$lines" | grep forwarded || true)
if grep -qF -- "$KEYBLOB default" <<<"$out" && grep -q '^signed$' <<<"$out" \
  && expect 2 "$fwd" ' allowed sign a Git commit or tag' "forwarded from $A" \
  && [ "$(count "$lines")" -eq 3 ] && never "$lines" ' reused .*forwarded'; then
  pass "2 forwarded ssh-keygen signatures"
else fail "2 forwarded ssh-keygen signatures"; show "$out"; fi
show "$lines"

echo "3. git commit -S twice inside A through the forwarded agent: forwarded, never reused"
m=$(mark)
out=$(remote -A "root@$A" "git init -q /root/repo && cd /root/repo \
  && git config gpg.format ssh && git config user.signingkey /root/key.pub \
  && echo \"t@t \$(cat /root/key.pub)\" >/root/allowed_signers \
  && git config gpg.ssh.allowedSignersFile /root/allowed_signers \
  && git config user.name t && git config user.email t@t \
  && git commit -q -S --allow-empty -m one && git commit -q -S --allow-empty -m two \
  && git log --format=%G? -2 | tr '\n' ' '")
lines=$(since "$m")
fwd=$(printf '%s' "$lines" | grep forwarded || true)
# %G? is G when the signature verifies against allowed_signers
if [ "$out" = "G G " ] && expect 2 "$fwd" ' allowed sign a Git commit or tag' "forwarded from $A" \
  && [ "$(count "$lines")" -eq 3 ] && never "$lines" ' reused .*forwarded'; then
  pass "3 forwarded git commits"
else fail "3 forwarded git commits"; show "$out"; fi
show "$lines"

echo "4. hop A -> B with the forwarded agent: login marked forwarded"
m=$(mark)
out=$(remote -A "root@$A" "ssh $REMOTE_SSH_OPTS root@$B hostname")
lines=$(since "$m")
fwd=$(printf '%s' "$lines" | grep forwarded || true)
if [ "$out" = kf-fwd-b ] && expect 1 "$fwd" ' allowed log in over SSH as root' "forwarded from $A" \
  && [ "$(count "$lines")" -eq 2 ]; then
  pass "4 forwarded hop login"
else fail "4 forwarded hop login"; show "$out"; fi
show "$lines"

echo "5. old client (no session-bind) as A: sign twice and hop, all forwarded, never reused"
start_sshd kf-fwd-old "$IMG_OLD"; OLD=$IP
version=$(remote "root@$OLD" 'ssh -V 2>&1')
echo "   OLD=$OLD: $version"
m=$(mark)
out=$(remote -A "root@$OLD" "echo one >/root/m1 && echo two >/root/m2 \
  && ssh-keygen -q -Y sign -n file -f /root/key.pub /root/m1 \
  && ssh-keygen -q -Y sign -n file -f /root/key.pub /root/m2 \
  && ssh $REMOTE_SSH_OPTS root@$B hostname")
lines=$(since "$m")
fwd=$(printf '%s' "$lines" | grep forwarded || true)
if grep -q '^OpenSSH_8\.[0-8]' <<<"$version" && [ "$out" = kf-fwd-b ] \
  && expect 3 "$fwd" ' allowed ' "forwarded from $OLD" \
  && [ "$(printf '%s' "$fwd" | grep -c 'sign data for file' || true)" -eq 2 ] \
  && [ "$(printf '%s' "$fwd" | grep -c 'log in over SSH as root' || true)" -eq 1 ] \
  && [ "$(count "$lines")" -eq 4 ] && never "$lines" ' reused .*forwarded'; then
  pass "5 old client forwarded"
else fail "5 old client forwarded"; show "$out"; fi
show "$lines"

# The local macOS ssh (8.9+) binds every forwarded channel itself with the
# forwarding flag, so 5 never reaches keyfob's fallback. Exercise it directly:
# a raw agent client that never sends session-bind, running as a process named
# `ssh` (the peer name is the executable's basename). Its last argument is the
# request: sshsig:<namespace> or login:<user>; the rest look like ssh's own
# arguments so the prompt gets a host.
mkdir "$WORK/fake"
cat >"$WORK/fake/client.c" <<'EOF'
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
static unsigned char buf[65536], *p;
static void u32(uint32_t v) { v = htonl(v); memcpy(p, &v, 4); p += 4; }
static void str(const void *s, size_t n) { u32((uint32_t)n); memcpy(p, s, n); p += n; }
static void txt(const char *s) { str(s, strlen(s)); }
static int io(int fd, size_t n) {  /* send buf[0..n), read reply into buf */
  unsigned char len[4]; uint32_t v = htonl((uint32_t)n);
  if (write(fd, &v, 4) != 4 || write(fd, buf, n) != (ssize_t)n) return -1;
  if (read(fd, len, 4) != 4) return -1;
  memcpy(&v, len, 4); v = ntohl(v);
  size_t done = 0;
  while (done < v) { ssize_t r = read(fd, buf + done, v - done); if (r <= 0) return -1; done += r; }
  return (int)v;
}
int main(int argc, char **argv) {
  const char *mode = argv[argc - 1];
  struct sockaddr_un a = {.sun_family = AF_UNIX};
  strncpy(a.sun_path, getenv("SSH_AUTH_SOCK"), sizeof a.sun_path - 1);
  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (connect(fd, (struct sockaddr *)&a, sizeof a)) return 2;
  buf[0] = 11;                                   /* request identities */
  if (io(fd, 1) < 9 || buf[0] != 12) return 3;
  uint32_t bloblen; memcpy(&bloblen, buf + 5, 4); bloblen = ntohl(bloblen);
  unsigned char blob[1024]; memcpy(blob, buf + 9, bloblen);
  unsigned char data[1024]; p = data;
  if (!strncmp(mode, "sshsig:", 7)) {            /* SSHSIG: namespace, reserved, hash alg, hash */
    memcpy(p, "SSHSIG", 6); p += 6; txt(mode + 7); txt(""); txt("sha512");
    unsigned char h[64] = {0}; str(h, 64);
  } else {                                       /* SSH_MSG_USERAUTH_REQUEST publickey */
    unsigned char sid[32] = {0}; str(sid, 32); *p++ = 50; txt(mode + 6);
    txt("ssh-connection"); txt("publickey"); *p++ = 1; txt("ecdsa-sha2-nistp256"); str(blob, bloblen);
  }
  size_t datalen = p - data;
  p = buf; *p++ = 13; str(blob, bloblen); str(data, datalen); u32(0);
  int n = io(fd, p - buf);
  return n > 0 && buf[0] == 14 ? 0 : 1;
}
EOF
cc -o "$WORK/fake/ssh" "$WORK/fake/client.c"
cp "$WORK/fake/ssh" "$WORK/fake/notssh"

echo "5b. fallback: non-login signature via a local peer named ssh that never bound"
m=$(mark)
"$WORK/fake/ssh" root@203.0.113.9 sshsig:file
"$WORK/fake/ssh" root@203.0.113.9 sshsig:file
lines=$(since "$m")
if expect 2 "$lines" ' allowed sign data for file' 'forwarded from 203.0.113.9'; then
  pass "5b fallback: unbound non-login via ssh"
else fail "5b fallback: unbound non-login via ssh"; fi
show "$lines"

echo "5c. fallback: login signature via a local peer named ssh that never bound"
m=$(mark)
"$WORK/fake/ssh" root@203.0.113.9 login:root
"$WORK/fake/ssh" root@203.0.113.9 login:root
lines=$(since "$m")
if expect 2 "$lines" ' allowed log in over SSH as root' 'forwarded from 203.0.113.9'; then
  pass "5c fallback: unbound login via ssh"
else fail "5c fallback: unbound login via ssh"; fi
show "$lines"

echo "5d. control: the same unbound requests from a peer not named ssh are not forwarded"
m=$(mark)
"$WORK/fake/notssh" root@203.0.113.9 sshsig:file
"$WORK/fake/notssh" root@203.0.113.9 login:root
lines=$(since "$m")
if [ "$(count "$lines")" -eq 2 ] && never "$lines" forwarded \
  && expect 1 "$(printf '%s' "$lines" | sed -n 1p)" ' allowed sign data for file' \
  && expect 1 "$(printf '%s' "$lines" | sed -n 2p)" ' allowed log in over SSH'; then
  pass "5d control: unbound requests not via ssh"
else fail "5d control: unbound requests not via ssh"; fi
show "$lines"

echo "6. control: two local commits, second reuses the approval, none forwarded"
git init -q "$WORK/repo"
git -C "$WORK/repo" config include.path "$KEYFOB_HOME/gitconfig"
m=$(mark)
for message in one two; do
  git -C "$WORK/repo" -c user.name=t -c user.email=t@t commit -q --allow-empty -m "$message"
done
lines=$(since "$m")
if [ "$(count "$lines")" -eq 2 ] && never "$lines" forwarded \
  && [ "$(printf '%s' "$lines" | sed -n 1p | awk '{print $2}')" = allowed ] \
  && [ "$(printf '%s' "$lines" | sed -n 2p | awk '{print $2}')" = reused ]; then
  pass "6 local commits reuse"
else fail "6 local commits reuse"; fi
show "$lines"

if [ "$FAILED" -ne 0 ]; then
  echo "agent log:"
  show "$(cat "$WORK/agent.log")"
  echo "FAILED"
  exit 1
fi
echo "ok"
