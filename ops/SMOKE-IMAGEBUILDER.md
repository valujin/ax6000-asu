# Standalone ImageBuilder smoke before catalog promotion

`smoke_imagebuilder.py` fills the gap between an approved builder-image import and catalog promotion. Its default is a **validated dry plan**: verify pinned local inputs and signatures, inspect the archive/source/overlay, and print the exact make argv. It does not contact Docker, run make, create an output directory, or write a smoke receipt. Local git/usign verification and temporary archive extraction still occur.

Only explicit `--run` starts bounded rootless containers and executes actual `make info`, `make manifest`, and `make image`. No actual archive/image smoke was performed while implementing the utility. Unit fixtures are synthetic and are not promotion evidence. There is no force, fixture-approval, skip-lock, or skip-inspection option.

## Prerequisites

- Actual native build verification evidence and its independently reviewed SHA256; the corresponding native RAW directory and original generated `profile.json`.
- The independently reviewed native source tree, at the exact source commit, including its existing built host inspection tools and source overlay. The runner reads it; it does not prepare or modify the source tree.
- If native verification ran inside a container, its recorded source paths may use a different namespace. Supply `--native-source-prefix` with that exact canonical absolute source prefix; it defaults to the actual host `--source`. For the verified 6.6 run, use `/build/retry1/source` while the actual host source is `/home/valuxin/dev/owrt/ax6000-packages-build/work/retry1/source`.
- The actual matching immutable ImageBuilder archive/SHA, independent builder approval receipt/SHA, and real [builder-image load receipt](BUILDER-IMAGE.md)/SHA. The explicit immutable image ID must agree with that load receipt.
- Actual signed snapshot manifest/SHA, its usign signature, production public usign key, and independently pinned host usign executable/SHA. Snapshot generation/cohort/profile/kernel identity and signature are checked. Promotion later verifies the complete signed tree inventory; this standalone smoke uses only the frozen native package bank and disables networking.
- A committed package-recipe repository at its independently approved full commit. Its `scripts`, `keys`, `profiles`, and `files` must be clean. Trusted native `verify-firmware.py` helpers are imported only from this checkout.
- For APK, an independently pinned **host** APK decoder/SHA, also used during native verification. Target binaries are never executed.
- Before `--run`, independent hard-kill lock evidence/SHA demonstrating that the same current global lock remains held after worker death and releases after container death. The existing operator proof is `/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/rootless-hardkill-proof.json`; independently review its actual bytes before selecting its SHA. The utility does not generate this authorization itself.

The hard-kill evidence contract is schema 1, kind `ax6000-rootless-lock-hardkill`, `ok:true`, exact `engine_id`, numeric `lock_device`/`lock_inode`, `held_after_worker_death:true`, and `released_after_container_death:true`. The current lock's stat must match. A replaced inode or different engine invalidates the proof.

## Invocation

Supply actual reviewed artifacts in place of the uppercase placeholders:

```bash
cd /home/valuxin/dev/owrt/ax6000-asu
/usr/bin/python3 ops/smoke_imagebuilder.py \
  --cohort 66 --image-id sha256:ACTUAL_LOADED_IMAGE_ID \
  --archive /actual/immutable-imagebuilder.tar.zst --archive-sha256 ACTUAL_IB_SHA \
  --profile /actual/native/raw/profile.json \
  --builder-approval /reviewed/ib-approval.json --builder-approval-sha256 APPROVED_SHA \
  --builder-load-receipt /actual/load-receipt.json --builder-load-receipt-sha256 REVIEWED_LOAD_SHA \
  --native-evidence /verified/native/evidence.json --native-evidence-sha256 REVIEWED_NATIVE_SHA \
  --snapshot-manifest /verified/snapshot/snapshot-manifest.json --snapshot-sha256 APPROVED_SNAPSHOT_SHA \
  --snapshot-signature /verified/snapshot/snapshot-manifest.sig \
  --public-key /trusted/package-recipe/keys/repository.pub \
  --usign /trusted/host/usign --usign-sha256 APPROVED_USIGN_SHA \
  --source /actual/native/source --native-source-prefix /build/retry1/source --raw /actual/native/raw \
  --package-repository /trusted/package-recipe --recipe-commit APPROVED_FULL_COMMIT \
  --output /fresh/operator-smoke
```

For actual execution, repeat the reviewed invocation and add:

```text
--run --lock-proof /reviewed/rootless-hardkill-proof.json --lock-proof-sha256 APPROVED_LOCK_PROOF_SHA
```

For `612-recommended` or `612-latest`, use that exact cohort and add `--apk /trusted/host/apk --apk-sha256 APPROVED_HOST_APK_SHA`. All three verified layouts are required; 6.6 runs stock only. Run as the trusted operator with existing production Docker access, without sudo or additional account/group changes. No public API or worker may invoke this operator utility.

The source-prefix option changes only path resolution. Every recorded tool/kernel path must be canonical, absolute and beneath that explicit prefix. Tools retain the exact `staging_dir/host/bin/fwtool` or `staging_dir/host/bin/unsquashfs4` suffix; the uncompressed kernel must resolve to an independently attested source-relative `Image`. The mapped host files still reject symlink components and require their complete approved tool/kernel SHA256, executable tool permissions, and the original native source commit. Wrong prefixes, traversal, foreign tools and changed bytes fail. No evidence file is rewritten and no `/build` host alias is created. Dry plans and smoke receipts record `native_source_mapping` with the proof prefix, actual source, and each original/relative/actual path plus digest. Omit the override when proof paths already use the actual source namespace.

## Execution and serialization

Every Docker operation uses an explicit guarded rootless client. The bounded disposable operator client uses the already approved local base image, user `2000:2000`, no network, a read-only root filesystem, all capabilities dropped, no-new-privileges, one CPU/2 GiB/no swap/128 tasks. It binds only the Docker CLI read-only, the dedicated `/run/user/2000/docker.sock`, and the exact overlay tar read-only when copying it. The production socket is never mounted into a client. Each call verifies dedicated engine `c592b58c-bc7e-40a0-91b5-29d5b29387a1` and rootless security before executing its explicit-socket command. Ambient Docker context/host variables cannot redirect it.

Each layout gets a newly created container from the approved immutable image. Only the shared host file `/home/valuxin/dev/owrt/ax6000-packages-build/work/.build.lock` is bound, read-only. User `1000:1000` runs an independent PID1 `timeout --foreground --kill-after=10s 1200 flock -x ...` holder. No make runs until a fresh random readiness token and actual `stat` device/inode prove acquisition of that same file. Worker/runner death does not transfer lock ownership back to the worker. PID1 timeout or container removal terminates the holder.

The runner verifies inspect declarations and actual kernel controls: CPU0–3, quota 400000/100000, memory 10737418240 bytes, swap zero, pids 2048, UID/GID 1000, zero effective capabilities, and no-new-privileges. Build containers have no network or privileged/extra mounts. All make commands use `nice -n 19 ionice -c 3`; host inspection also lowers its own priority, with existing native helpers applying bounded CPU/memory/output limits. Cleanup removes only the newly created container ID.

Package requests start with actual installed names from the original native device manifest, whose bytes/hash/names are checked against native proof. Tailscale is removed and explicitly excluded from make requests. Both managers preserve actual names and **omit STRIP_ABI**. Preflight and emitted manifests must retain native defaults, contain only exact approved native-bank versions, preserve the matching kernel/manager/vendor stack, exclude Tailscale/foreign radio packages, and equal each other. The receipt references the manifest actually emitted by `make image`, rather than preflight stdout.

The rootfs FILES overlay comes from the shared promoter `rootfs_overlay` helper: exactly five reviewed OPKG paths or seven APK paths, with each actual source byte/mode checked against every native proof layout and the committed renderer. It is copied into `/builder/smoke-files`; no extra source files or private keys are copied. This **pre-catalog standalone** image preserves the native four-field `/etc/asu-cohort.json` bytes, because the final catalog SHA does not exist yet. Later HTTP acceptance must exercise the server's full eight-field catalog identity override. APK's protected world list is regenerated by the approved IB policy rather than copied from the native root.

Actual stdout and stderr for all three make operations are retained. The runner exports generated `profiles.json`, image manifests, and image artifacts with bounded, link-free extraction. The approved native host fwtool extracts real image metadata; trusted native helpers inspect the actual TAR/FIT payload, layout DTB/partition geometry, uncompressed kernel, SquashFS package DB, repository/ASU overlay, vendor firmware/modules, package versions, and optional features. Kernel/module/firmware/repository/feature hashes must also agree with independent native evidence. No router binary or script is run.

## Receipt and remaining acceptance

Only after every layout succeeds does `evidence.json` appear. It matches [the promoter smoke contract](PROMOTION.md): exact generation/source/kernel/target identity, archive/attestation/snapshot hashes, per-layout zero exit codes and relative regular-file `{path,size,sha256}` records for actual info, emitted manifest, sysupgrade image, fwtool metadata, plus native uncompressed kernel SHA. It additionally records image/engine, native/hard-kill receipt hashes, lock identity, profiles and detailed root inspection. All referenced files remain under the fresh output directory. Partial failures retain logs for diagnosis and do not produce an accepted final receipt.

The utility does not promote a catalog, start APIs, publish artifacts, sign firmware, flash a router, test hardware boot, or execute personalized Tailscale acceptance. The independently reviewed receipt SHA is an input to the later promotion step. After promotion, actual HTTP/worker acceptance must test final catalog identity, personalized package policy, queue behavior and output delivery.

## Tests

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s ops/tests -p test_smoke_imagebuilder.py -v
```

Synthetic fixtures cover dry-plan engine isolation, no missing-proof bypass, container-to-host source namespace mapping and wrong-prefix/traversal/hash/symlink rejection, shell-safe argv/actual package names, PID1 lock command, fresh nonce/inode matching, resource/privilege failures, exact overlay bytes/modes, export traversal/link rejection, manifest policies, native root hash drift, and receipt compatibility/tamper rejection against the real promoter validator. These tests create no Docker containers and provide no production smoke evidence.
