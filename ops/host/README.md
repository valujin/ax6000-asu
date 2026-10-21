This one-off setup creates a separate rootless Docker engine for the ASU builder on 161.97.154.64. The production engine remains at `/var/run/docker.sock`. The three executable/helper/test files here are byte-identical copies of the reviewed scripts that the operator already applied from `/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/deployment-host`; that applied original has not been altered.

The operator completed `--apply` and `--verify` on 2026-10-21. The dedicated account is `ax6000-asu-build`, UID/GID `2000:2000`, engine `c592b58c-bc7e-40a0-91b5-29d5b29387a1`, socket `/run/user/2000/docker.sock`. Rootless/systemd cgroup v2 and actual CPU0–3/four-CPU quota, 10 GiB memory, zero swap, and 2,048 tasks were verified. Production's 19 running services were preserved. This host does **not** need another root setup step. The saved [independent engine info](evidence/rootless-independent-info.json) records engine identity and reported cgroup capabilities.

For a new matching host only, review `setup-rootless.sh` and `host_checks.py`, then run:

```bash
cd /home/valuxin/dev/owrt/ax6000-asu/ops/host
./setup-rootless.sh --check
# The operator supplies the sudo password; this is the actual host-changing step.
sudo /bin/bash ./setup-rootless.sh --apply
sudo /bin/bash ./setup-rootless.sh --verify
cat /run/ax6000-asu-rootless/engine.env
```

`--check` is read-only. `--apply` installs the single requested package `uidmap` with `--no-upgrade --no-install-recommends --no-remove`. The current APT simulation also requires **libsubid4**, a dependency of uidmap. The script rejects other packages, upgrades, and removals; it does not update APT indexes or remove packages. `NEEDRESTART_MODE=l` prevents unrelated service restarts through needrestart. Recheck the printed simulation before applying after a host/package change.

It allocates a fresh `ax6000-asu-build` UID, a private mode-0700 home `/home/ax6000-asu-build`, and a non-overlapping pair of 65,536 subordinate UID/GID ranges. The account has a locked password/default useradd behavior, a nologin shell, and only its own group plus `ax6000-asu-lock`. It is never added to docker or sudo. Unexpected existing accounts, homes, groups, daemon sockets, modified managed files, and engine identity drift stop setup. Root-owned markers in `/var/lib/ax6000-asu-rootless` allow idempotent re-runs after partial setup; investigate failures rather than deleting markers or adopting existing data.

Only `user@<dedicated UID>.service` gets `Delegate=cpu cpuset memory pids io`. Only `user-<dedicated UID>.slice` gets CPU affinity 0–3, a four-CPU quota, 10 GiB memory, zero swap, and 2,048 tasks. The slice caps include daemon overhead and all containers for this account, providing an aggregate ceiling. The user Docker service delegates all five controllers. No `user@.service` template, production Docker unit/configuration, valuxin Docker context, or global sysctl is edited. It does not run the Docker rootless setup tool because that tool changes a CLI context; the dedicated user unit is created directly.

Ubuntu already has `/etc/apparmor.d/rootlesskit`, granting `userns` to `/usr/bin/rootlesskit`. The script inspects and, only if absent from the loaded profiles, loads this packaged profile. It keeps `kernel.apparmor_restrict_unprivileged_userns=1`. If the expected profile is missing/disabled/unexpected, setup stops for review rather than generating a broad profile or disabling security.

For the existing native/global flock, the script adds only a named-user **search (`--x`) ACL on `/home/valuxin`**. Other ancestors already permit traversal. It preserves the existing owner/group/other permissions and ACL mask, and refuses an ACL that would require expanding that mask. This uses Ubuntu's existing libacl through Python; no acl package is installed. It changes the existing `.build.lock` inode to group `ax6000-asu-lock`, mode 0660, retaining owner valuxin. It does not recreate the lock, open other directories, change the native user's groups, or wait for/acquire the build lock during setup. It checks native access and forks subprocesses with the worker's exact UID, primary GID, and explicit supplementary lock group; a negative probe with supplementary groups cleared must fail. The worker should bind only this file and hold an exclusive flock for each complete build; its queue and singleton are application responsibilities.

The runtime also needs the narrower, separately reviewed **read-only named-user ACL for the host UID mapped from container UID 1000**. This additional ACL is already installed on this host and is not part of the historical root setup script. `/etc/subuid` assigns `ax6000-asu-build:196608:65536`; rootless container UID 0 maps to host UID 2000, while container UID 1000 maps to `196608 + 1000 - 1 = 197607`. The [actual ACL receipt](evidence/rootless-lock-acl.json) records:

```text
user::rw-
user:197607:r--
group::rw-
mask::rw-
other::---
```

Only read permission is needed because container PID1 opens the bind-mounted lock read-only and holds an exclusive flock. The inode remains `8156582` on device `2049`; owner/group/other access and the mask were preserved. Do not add the mapped UID to a host group or grant it directory traversal: only this file is mounted into build containers. The [actual hard-kill receipt](evidence/rootless-hardkill-proof.json) proves the lock remained held after worker SIGKILL and was released after container death, using this exact device/inode and engine.

For a new deployment, determine the mapping from its actual `/etc/subuid` entry rather than copying 197607 blindly. A file-owner operator with existing `setfacl` tooling can review this minimal grant after confirming the lock's current mode/mask is 0660/rw- and its inode is unchanged:

```bash
LOCK=/home/valuxin/dev/owrt/ax6000-packages-build/work/.build.lock
MAPPED_UID=$(/usr/bin/python3 - <<'PY'
rows = [line.strip().split(':') for line in open('/etc/subuid')
        if line.startswith('ax6000-asu-build:')]
assert len(rows) == 1 and int(rows[0][2]) >= 1000
print(int(rows[0][1]) + 999)
PY
)
stat -c 'device=%d inode=%i mode=%a owner=%U group=%G' "$LOCK"
getfacl --absolute-names "$LOCK"
# Only on the new host, after reviewing the current file/mask:
setfacl --no-mask --modify "u:${MAPPED_UID}:r--,m::rw-" "$LOCK"
```

This documentation does not install ACL tooling or run the grant. On the already configured host, leave the ACL as recorded. Any future root-setup re-run must retain/recheck this separate read-only entry; the copied historical script is intentionally unchanged. Repeat the independent PID1 hard-kill/inode proof before accepting actual builds on a new deployment.

Setup verifies Docker `SecurityOptions=name=rootless`, cgroup v2/systemd, all reported cgroup capabilities, a dedicated data directory/socket owner, and an engine ID different from production before any image pull or container run. It pins the first successful engine ID and refuses subsequent identity changes. It pulls `docker.io/library/busybox:1.37.0` **into the rootless engine only**, records its resolved digest, and runs a disposable non-root, no-network, read-only probe with all capabilities dropped. The probe reads kernel cgroup files and requires exact effective CPU0–3/four-CPU quota, memory=10737418240, swap=0, pids=2048. The slice's actual kernel limits are checked too. `--verify` repeats a container probe using the locally recorded digest; it is not read-only, but does not install packages or change accounts/services. Root setup creates the rootless `asu-build` network and rejects an existing network without its managed label. Production engine ID and running-container IDs are compared before/after; an external concurrent change causes failure for inspection.

The readable `/run/ax6000-asu-rootless/engine.env` contains non-secret deployment inputs. Copy these values into the deployment's persistent environment configuration after review; `/run` is ephemeral across reboot. The root-only persistent copy is `/var/lib/ax6000-asu-rootless/engine.env`. Linger and systemd restart the dedicated engine after reboot without rerunning setup.

- Run the worker container as `ASU_BUILD_UID:ASU_BUILD_GID` so it can open the dedicated socket. Do not assume UID 1000.
- Set worker Compose `group_add: ["${ASU_BUILD_LOCK_GID:?}"]` using the emitted numeric lock-group GID. Docker containers do not inherit the host account's supplementary groups; omitting this setting prevents access to the global lock.
- Bind `ASU_ROOTLESS_SOCKET` to `/run/ax6000-build/docker.sock` and use the emitted `ASU_BUILD_ENGINE_URL` explicitly; check the emitted `ASU_BUILD_ENGINE_ID` and rootless security option on every worker startup.
- Bind the exact emitted `ASU_BUILD_LOCK` file to the worker lock path. The native builder continues to use the same host inode.
- Keep build containers capped with `--cpus=4 --cpuset-cpus=0-3 --memory=10g --memory-swap=10g --pids-limit=2048`; the aggregate user slice is an additional ceiling. Verify these actual caps before accepting queued builds.
- API/Redis containers must not receive the rootless or production socket. A bounded queue and exactly one build worker remain required.

Static/local verification, without root setup:

```bash
bash -n setup-rootless.sh
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest -v test_host_checks.py
```

Initial `--check` is for a new host. On this configured host, the unprivileged check intentionally cannot inspect the root-only setup marker; no new root check is needed merely to validate these copied files.

The tests exercise unsafe APT plans, subordinate-ID overlaps, rootful/mismatched engines, missing capabilities, effective-cap mismatches, idempotent minimal ACL changes on temporary fixtures inside this directory, and the worker credential/probe failure paths. Credential tests simulate access decisions and never acquire root or change host credentials. Tests do not substitute for actual host checks: the operator already completed `--apply`/`--verify` and the separate mapped-UID ACL/hard-kill verification on the documented host. A new deployment must establish its own actual checks.

References: [Docker rootless tips and cgroup delegation](https://docs.docker.com/engine/security/rootless/tips/), [Docker rootless prerequisites](https://docs.docker.com/engine/security/rootless/), [systemd resource controls](https://freedesktop.org/software/systemd/man/latest/systemd.resource-control.html).
