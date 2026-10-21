#!/bin/bash
# Reviewed one-off root setup. --check is read-only and works as valuxin.
set -Eeuo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C
unset DOCKER_HOST DOCKER_CONTEXT DOCKER_TLS_VERIFY DOCKER_CERT_PATH
umask 077
BASE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CHECKS=$BASE/host_checks.py
USER_NAME=ax6000-asu-build
BUILD_HOME=/home/ax6000-asu-build
LOCK_GROUP=ax6000-asu-lock
BUILD_LOCK=/home/valuxin/dev/owrt/ax6000-packages-build/work/.build.lock
STATE=/var/lib/ax6000-asu-rootless
MODE=${1:---check}
PROBE_IMAGE=docker.io/library/busybox:1.37.0
fail() { echo "ERROR: $*" >&2; exit 1; }
trap 'echo "Failed at line $LINENO. No production Docker restart is attempted; inspect the dedicated user service before resuming." >&2' ERR
[[ $# -le 1 && ( $MODE == --check || $MODE == --apply || $MODE == --verify ) ]] || fail 'Usage: setup-rootless.sh [--check|--apply|--verify]'
for tool in python3 docker dockerd-rootless.sh rootlesskit runc slirp4netns runuser systemctl loginctl flock apt-get apparmor_parser; do
    command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool"
done
[[ -f /sys/fs/cgroup/cgroup.controllers ]] || fail 'cgroup v2 required'
for controller in cpu cpuset memory pids io; do
    [[ " $(cat /sys/fs/cgroup/cgroup.controllers) " == *" $controller "* ]] || fail "Missing cgroup controller: $controller"
done
[[ $(readlink -f /usr/bin/rootlesskit) == /usr/bin/rootlesskit ]] || fail 'Unexpected rootlesskit installation'
[[ -f /etc/apparmor.d/rootlesskit ]] || fail 'Packaged rootlesskit AppArmor profile missing: review a path-specific userns profile; do not disable userns restrictions'
[[ ! -e /etc/apparmor.d/disable/rootlesskit ]] || fail 'Packaged rootlesskit AppArmor profile disabled'
rg_profile=$(cat /etc/apparmor.d/rootlesskit)
[[ $rg_profile == *'/usr/bin/rootlesskit'* && $rg_profile == *'userns,'* ]] || fail 'Review unexpected packaged rootlesskit profile'
[[ -f $BUILD_LOCK && ! -L $BUILD_LOCK && $(stat -c %U "$BUILD_LOCK") == valuxin ]] || fail 'Expected existing valuxin-owned lock file (never recreate it)'
[[ $(stat -c %h "$BUILD_LOCK") == 1 ]] || fail 'Unexpected hardlinked lock file'
[[ $(stat -c %U /home/valuxin) == valuxin && ! -L /home/valuxin ]] || fail 'Unexpected valuxin home'
# Resolve all ancestors: symlinks would grant access outside the reviewed directory tree.
[[ $(realpath -e "$BUILD_LOCK") == "$BUILD_LOCK" ]] || fail 'Symlink in lock path'
PYTHON=/usr/bin/python3
$PYTHON -c 'import ctypes,ctypes.util; assert ctypes.util.find_library("acl")'
APT_PLAN=$(apt-get --simulate --no-upgrade --no-install-recommends --no-remove install uidmap)
printf '%s\n' "$APT_PLAN" | "$PYTHON" "$CHECKS" apt
printf 'APT simulation:\n%s\n' "$APT_PLAN"
if [[ $MODE == --check ]]; then
    printf 'Read-only preflight: packaged AppArmor profile found; cgroup v2 controllers present.\n'
    if getent passwd "$USER_NAME" >/dev/null; then
        [[ -r $STATE/account.env ]] || fail 'Existing account without readable managed marker; root must inspect'
        printf 'Dedicated account exists; use root --verify for full ownership/daemon/cap checks.\n'
    else
        [[ ! -e $BUILD_HOME && ! -e $STATE && ! -e /run/ax6000-asu-rootless ]] || fail 'Unexpected home/state without dedicated user'
        getent group "$LOCK_GROUP" >/dev/null && fail 'Unexpected pre-existing lock group'
        printf 'Dedicated account is absent. Apply will create a fresh account and non-overlapping subordinate IDs.\n'
    fi
    command -v newuidmap >/dev/null || printf 'newuidmap/newgidmap missing: apply must install uidmap (and only the simulated libsubid4 dependency).\n'
    printf 'No account, package, filesystem permission, service, or Docker changes made.\n'
    exit 0
fi
[[ $EUID == 0 ]] || fail '--apply/--verify must run as root'
# This lock serializes setup only. The native/build-worker lock is never acquired here.
exec 9>/run/lock/ax6000-asu-rootless-setup.lock
flock -n 9 || fail 'Another setup/verify is running'
PRODUCTION_BEFORE=$(docker --host unix:///var/run/docker.sock info --format '{{.ID}}')
PRODUCTION_RUNNING_BEFORE=$(docker --host unix:///var/run/docker.sock ps --quiet --no-trunc | sort)
if [[ $MODE == --apply && ! -d $STATE ]]; then
    getent passwd "$USER_NAME" >/dev/null && fail 'Refusing to adopt existing user'
    getent group "$USER_NAME" >/dev/null && fail 'Refusing to adopt existing primary group'
    getent group "$LOCK_GROUP" >/dev/null && fail 'Refusing to adopt existing lock group'
    [[ ! -e $BUILD_HOME ]] || fail 'Refusing to adopt existing home'
    BUILD_UID=2000
    while getent passwd "$BUILD_UID" >/dev/null || getent group "$BUILD_UID" >/dev/null; do BUILD_UID=$((BUILD_UID + 1)); done
    (( BUILD_UID < 60000 )) || fail 'No free UID'
    SUBID_START=$($PYTHON "$CHECKS" subids /etc/subuid /etc/subgid)
    install -d -m 0700 -o root -g root "$STATE"
    printf 'BUILD_UID=%s\nSUBID_START=%s\n' "$BUILD_UID" "$SUBID_START" > "$STATE/account.env"
fi
[[ ! -L $STATE && -f $STATE/account.env && ! -L $STATE/account.env && $(stat -c %u:%a "$STATE") == 0:700 && $(stat -c %u:%a "$STATE/account.env") == 0:600 ]] || fail 'Missing or untrusted setup marker'
# Parse fixed integer fields without sourcing a file as root.
BUILD_UID=$(sed -n 's/^BUILD_UID=\([0-9]\+\)$/\1/p' "$STATE/account.env")
SUBID_START=$(sed -n 's/^SUBID_START=\([0-9]\+\)$/\1/p' "$STATE/account.env")
[[ $BUILD_UID =~ ^[0-9]+$ && $SUBID_START =~ ^[0-9]+$ ]] || fail 'Invalid setup marker'
if [[ $MODE == --apply ]]; then
    # needrestart list mode prevents unrelated service restarts from the package hook.
    DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l apt-get --yes --no-upgrade --no-install-recommends --no-remove install uidmap
    if ! getent passwd "$USER_NAME" >/dev/null; then
        [[ ! -e $BUILD_HOME ]] || fail 'Unexpected home after partial setup'
        useradd --uid "$BUILD_UID" --user-group --create-home --home-dir "$BUILD_HOME" --shell /usr/sbin/nologin -K SUB_UID_COUNT=0 -K SUB_GID_COUNT=0 "$USER_NAME"
        chmod 0700 "$BUILD_HOME"
    fi
    [[ $(id -u "$USER_NAME") == "$BUILD_UID" && $(getent passwd "$USER_NAME" | cut -d: -f6-7) == "$BUILD_HOME:/usr/sbin/nologin" ]] || fail 'Unexpected account after partial setup'
    [[ ! -L $BUILD_HOME && $(stat -c %u:%a "$BUILD_HOME") == "$BUILD_UID:700" ]] || fail 'Unexpected account home after partial setup'
    getent group "$LOCK_GROUP" >/dev/null || groupadd --system "$LOCK_GROUP"
    usermod --append --groups "$LOCK_GROUP" "$USER_NAME"
    for map in /etc/subuid /etc/subgid; do
        if ! grep -q "^$USER_NAME:" "$map"; then
            flag=--add-subuids; [[ $map == /etc/subgid ]] && flag=--add-subgids
            usermod "$flag" "$SUBID_START-$((SUBID_START + 65535))" "$USER_NAME"
        fi
    done
fi
[[ $(id -u "$USER_NAME") == "$BUILD_UID" ]] || fail 'Unexpected account UID'
[[ $(getent passwd "$USER_NAME" | cut -d: -f6-7) == "$BUILD_HOME:/usr/sbin/nologin" ]] || fail 'Unexpected home/shell'
[[ $(stat -c %u:%a "$BUILD_HOME") == "$BUILD_UID:700" && ! -L $BUILD_HOME ]] || fail 'Unexpected home owner/mode'
BUILD_GID=$(id -g "$USER_NAME")
BUILD_LOCK_GID=$(getent group "$LOCK_GROUP" | cut -d: -f3)
[[ $BUILD_LOCK_GID =~ ^[0-9]+$ ]] || fail 'Missing dedicated build-lock group'
[[ $(id -Gn "$USER_NAME" | tr ' ' '\n' | sort | tr '\n' ' ') == "$(printf '%s\n%s\n' "$USER_NAME" "$LOCK_GROUP" | sort | tr '\n' ' ')" ]] || fail 'Unexpected supplementary groups (Docker/sudo membership forbidden)'
for map in /etc/subuid /etc/subgid; do
    [[ $(grep "^$USER_NAME:" "$map") == "$USER_NAME:$SUBID_START:65536" ]] || fail "Unexpected mapping in $map"
    "$PYTHON" - "$map" "$USER_NAME" "$SUBID_START" <<'PY'
import sys
path, name, begin = sys.argv[1:]; begin = int(begin)
for row in open(path):
    who, start, count = row.strip().split(':'); start, count = int(start), int(count)
    if who != name and begin < start + count and start < begin + 65536:
        raise SystemExit('Overlapping subordinate ID allocation')
PY
done
command -v newuidmap >/dev/null && command -v newgidmap >/dev/null || fail 'uidmap helpers missing'
RUNTIME=/run/user/$BUILD_UID
SOCKET=$RUNTIME/docker.sock
as_user() { runuser -u "$USER_NAME" -- env -i HOME="$BUILD_HOME" USER="$USER_NAME" LOGNAME="$USER_NAME" PATH="$PATH" XDG_RUNTIME_DIR="$RUNTIME" DBUS_SESSION_BUS_ADDRESS="unix:path=$RUNTIME/bus" "$@"; }
docker_user() { as_user /usr/bin/docker --host "unix://$SOCKET" "$@"; }
if [[ $MODE == --apply ]]; then
    # Existing files are immutable through this installer: fail on drift, never overwrite.
    put_file() {
        local target=$1 owner=$2 mode=$3 tmp
        tmp=$(mktemp "$STATE/staged.XXXXXX")
        cat > "$tmp"
        if [[ -e $target || -L $target ]]; then
            [[ ! -L $target && -f $target ]] && cmp -s "$tmp" "$target" || fail "Unexpected managed file: $target"
            [[ $(stat -c %u:%a "$target") == "$(id -u "$owner"):${mode#0}" ]] || fail "Unexpected managed file owner/mode: $target"
            rm "$tmp"
        else
            install -m "$mode" -o "$owner" -g "$(id -gn "$owner")" "$tmp" "$target"
            rm "$tmp"
        fi
    }
    for directory in /etc/systemd/system/user@"$BUILD_UID".service.d /etc/systemd/system/user-"$BUILD_UID".slice.d; do
        [[ ! -L $directory ]] || fail "Symlink in dedicated systemd configuration: $directory"
        install -d -m 0755 -o root -g root "$directory"
    done
    put_file /etc/systemd/system/user@"$BUILD_UID".service.d/50-ax6000-asu.conf root 0644 <<'EOF'
[Service]
Delegate=cpu cpuset memory pids io
EOF
    put_file /etc/systemd/system/user-"$BUILD_UID".slice.d/50-ax6000-asu.conf root 0644 <<'EOF'
[Slice]
AllowedCPUs=0-3
CPUQuota=400%
MemoryMax=10737418240
MemorySwapMax=0
TasksMax=2048
EOF
    for directory in "$BUILD_HOME/.config" "$BUILD_HOME/.config/systemd" "$BUILD_HOME/.config/systemd/user" "$BUILD_HOME/.config/docker"; do
        [[ ! -L $directory ]] || fail "Symlink in dedicated config directory: $directory"
        install -d -m 0700 -o "$USER_NAME" -g "$BUILD_GID" "$directory"
    done
    put_file "$BUILD_HOME/.config/systemd/user/docker.service" "$USER_NAME" 0600 <<EOF
[Unit]
Description=Dedicated ASU Rootless Docker
Documentation=https://docs.docker.com/engine/security/rootless/
[Service]
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
Environment=DOCKERD_ROOTLESS_ROOTLESSKIT_NET=slirp4netns
ExecStart=/usr/bin/dockerd-rootless.sh --host=unix://$SOCKET --config-file=$BUILD_HOME/.config/docker/daemon.json
ExecReload=/bin/kill -s HUP \$MAINPID
TimeoutStartSec=180
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576
TasksMax=infinity
Delegate=cpu cpuset memory pids io
KillMode=mixed
[Install]
WantedBy=default.target
EOF
    put_file "$BUILD_HOME/.config/docker/daemon.json" "$USER_NAME" 0600 <<EOF
{"data-root":"$BUILD_HOME/.local/share/docker","exec-opts":["native.cgroupdriver=systemd"],"log-driver":"local","log-opts":{"max-size":"10m","max-file":"3"}}
EOF
    # The packaged /usr/bin/rootlesskit profile already grants only that program userns.
    # Load it only if absent; no global AppArmor/sysctl changes and no generic profile.
    if ! grep -q '^rootlesskit (' /sys/kernel/security/apparmor/profiles; then
        apparmor_parser --add /etc/apparmor.d/rootlesskit
    fi
    "$PYTHON" "$CHECKS" traverse /home/valuxin "$BUILD_UID"
    chgrp "$LOCK_GROUP" "$BUILD_LOCK"
    chmod 0660 "$BUILD_LOCK"
    systemctl daemon-reload
    if [[ ! -e $STATE/startup-authorized ]]; then
        [[ ! -S $SOCKET ]] || fail 'Unexpected unrecorded daemon socket'
        # Existing process/session would need a separate review before delegation applies.
        if systemctl is-active --quiet user@"$BUILD_UID".service; then
            fail 'Unexpected running user manager before first startup'
        fi
        touch "$STATE/startup-authorized"
    fi
    loginctl enable-linger "$USER_NAME"
    systemctl start user@"$BUILD_UID".service
    # user@ service activation normally makes this ready; tolerate a short bus startup.
    for attempt in {1..30}; do
        if as_user systemctl --user show-environment >/dev/null 2>&1; then break; fi
        sleep 1
    done
    as_user systemctl --user daemon-reload
    as_user systemctl --user enable --now docker.service
fi
# No image pull/run occurs before verifying the dedicated daemon's identity and features.
EXPECTED_ID=''
[[ ! -f $STATE/engine-id ]] || EXPECTED_ID=$(cat "$STATE/engine-id")
for attempt in {1..60}; do
    if docker_user info --format '{{json .}}' > "$STATE/info.tmp" 2>/dev/null; then break; fi
    sleep 1
done
ENGINE_ID=$("$PYTHON" "$CHECKS" info ${EXPECTED_ID:+"$EXPECTED_ID"} < "$STATE/info.tmp")
[[ $(docker_user info --format '{{.DockerRootDir}}') == "$BUILD_HOME/.local/share/docker" ]] || fail 'Unexpected dedicated Docker data directory'
PRODUCTION_ID=$(docker --host unix:///var/run/docker.sock info --format '{{.ID}}')
[[ $ENGINE_ID != "$PRODUCTION_ID" ]] || fail 'Dedicated engine equals production engine'
[[ $PRODUCTION_ID == "$PRODUCTION_BEFORE" ]] || fail 'Production engine identity changed during setup'
[[ $(stat -c %u "$SOCKET") == "$BUILD_UID" ]] || fail 'Unexpected socket owner'
[[ $(loginctl show-user "$USER_NAME" -p Linger --value) == yes ]] || fail 'Dedicated account lacks linger'
[[ $(systemctl show user@"$BUILD_UID".service -p Delegate --value) == yes ]] || fail 'User manager not delegated'
USER_CGROUP=$(systemctl show user@"$BUILD_UID".service -p ControlGroup --value)
SLICE_CGROUP=$(systemctl show user-"$BUILD_UID".slice -p ControlGroup --value)
[[ $USER_CGROUP == /user.slice/user-"$BUILD_UID".slice/user@"$BUILD_UID".service ]] || fail 'Unexpected user cgroup path'
[[ $SLICE_CGROUP == /user.slice/user-"$BUILD_UID".slice ]] || fail 'Unexpected slice path'
for controller in cpu cpuset memory pids io; do
    [[ " $(cat "/sys/fs/cgroup$USER_CGROUP/cgroup.controllers") " == *" $controller "* ]] || fail "Controller not delegated: $controller"
done
for file in cpu.max cpuset.cpus.effective memory.max memory.swap.max pids.max; do
    printf '%s=%s\n' "$file" "$(cat "/sys/fs/cgroup$SLICE_CGROUP/$file")"
done | "$PYTHON" "$CHECKS" caps
# Test that both identities can open the same inode. Do not contend with an active build.
"$PYTHON" "$CHECKS" worker-lock "$BUILD_LOCK" "$BUILD_UID" "$BUILD_GID" "$BUILD_LOCK_GID"
runuser -u valuxin -- /usr/bin/python3 -c 'import os,sys; fd=os.open(sys.argv[1],os.O_RDWR); os.close(fd)' "$BUILD_LOCK"
[[ $(stat -c %a:%G "$BUILD_LOCK") == "660:$LOCK_GROUP" ]] || fail 'Unexpected lock permissions'
if [[ $MODE == --apply ]]; then
    [[ -n $EXPECTED_ID ]] || printf '%s\n' "$ENGINE_ID" > "$STATE/engine-id"
    # Pull is exclusively into the verified rootless engine. The resolved digest is recorded.
    docker_user pull "$PROBE_IMAGE"
    PROBE_DIGEST=$(docker_user image inspect "$PROBE_IMAGE" --format '{{index .RepoDigests 0}}')
    [[ $PROBE_DIGEST == *@sha256:* ]] || fail 'Probe image did not resolve to a digest'
    printf '%s\n' "$PROBE_DIGEST" > "$STATE/probe-image"
else
    [[ -f $STATE/probe-image ]] || fail 'Missing successful probe image record'
    PROBE_DIGEST=$(cat "$STATE/probe-image")
fi
# Read the effective kernel limits from a running unprivileged container. Inspect alone
# cannot prove delegation; rootless Docker can otherwise silently ignore resource flags.
docker_user run --rm --pull=never --network none --read-only --user 65534:65534 \
    --cap-drop ALL --security-opt no-new-privileges --cpus 4 --cpuset-cpus 0-3 \
    --memory 10g --memory-swap 10g --pids-limit 2048 "$PROBE_DIGEST" \
    sh -ec 'for x in cpu.max cpuset.cpus.effective memory.max memory.swap.max pids.max; do printf "%s=%s\n" "$x" "$(cat /sys/fs/cgroup/$x)"; done' \
    | "$PYTHON" "$CHECKS" caps
if [[ $MODE == --apply ]]; then
    if ! docker_user network inspect asu-build >/dev/null 2>&1; then
        docker_user network create --label by.ezon.asu.managed=rootless-setup asu-build >/dev/null
    fi
    [[ $(docker_user network inspect asu-build --format '{{index .Labels "by.ezon.asu.managed"}}') == rootless-setup ]] || fail 'Unexpected existing asu-build network'
    [[ $(docker --host unix:///var/run/docker.sock ps --quiet --no-trunc | sort) == "$PRODUCTION_RUNNING_BEFORE" ]] || fail 'Production running container set changed during setup; inspect before deployment'
    # Publish a non-secret Compose env contract only after all checks pass.
    [[ ! -L /run/ax6000-asu-rootless ]] || fail 'Unexpected runtime contract symlink'
    install -d -m 0755 -o root -g root /run/ax6000-asu-rootless
    cat > "$STATE/engine.env.new" <<EOF
ASU_BUILD_UID=$BUILD_UID
ASU_BUILD_GID=$BUILD_GID
ASU_BUILD_LOCK_GID=$BUILD_LOCK_GID
ASU_ROOTLESS_SOCKET=$SOCKET
ASU_BUILD_ENGINE_ID=$ENGINE_ID
ASU_BUILD_ENGINE_URL=unix:///run/ax6000-build/docker.sock
ASU_BUILD_LOCK=$BUILD_LOCK
ASU_BUILD_NETWORK=asu-build
EOF
    chmod 0644 "$STATE/engine.env.new"
    mv "$STATE/engine.env.new" "$STATE/engine.env"
    install -m 0644 -o root -g root "$STATE/engine.env" /run/ax6000-asu-rootless/engine.env
fi
rm -f "$STATE/info.tmp"
[[ $(docker --host unix:///var/run/docker.sock ps --quiet --no-trunc | sort) == "$PRODUCTION_RUNNING_BEFORE" ]] || fail 'Production running container set changed during setup; inspect before deployment'
printf 'Verified dedicated rootless engine: %s\nSocket: unix://%s\nCompose contract: /run/ax6000-asu-rootless/engine.env\nPersistent contract: %s/engine.env\n' "$ENGINE_ID" "$SOCKET" "$STATE"
printf 'Effective limits verified: CPU0-3 / quota4, memory10GiB, swap0, pids2048.\n'
