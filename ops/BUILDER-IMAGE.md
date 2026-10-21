# Operator-only ImageBuilder image preparation

`builder_image.py` packages an **already independently verified native ImageBuilder archive** into a Docker image and, only with `--build-load`, imports that immutable image into the dedicated rootless engine. It never downloads an archive, pulls a base, invokes a setup URL, installs dependencies, changes a Docker context, starts a service, or promotes a catalog.

The default command validates local files, unpacks them into a temporary directory, scans the tree, prints its plan, then removes that temporary directory. It does **not** contact either Docker engine. There is no real production ImageBuilder archive, build, or import receipt supplied by these fixtures.

## Inputs and trust

Provide the archive and its actual SHA256, generated native `profile.json`, the production **public usign key**, and a separately reviewed approval receipt with its independently supplied SHA256. Computing the receipt SHA from a newly invented receipt does not constitute independent review. Run the existing native package repository's `imagebuilder.verify_archive(...)` against the actual native source tree/package bank with its real host usign binary first. Preserve the original verifier result and review its archive/profile/public-key/kernel-context/signature evidence before approving this wrapper receipt.

Approval schema (all values below are placeholders, **not an approved receipt**):

```json
{
  "schema_version": 1,
  "kind": "ax6000-imagebuilder-approval",
  "approved": true,
  "source_context_verified": true,
  "native_bank_verified": true,
  "signatures_verified": true,
  "private_keys_absent": true,
  "cohort": "66",
  "package_manager": "opkg",
  "build_id": "ACTUAL_NATIVE_BUILD_ID",
  "source_commit": "ACTUAL_40_HEX_COMMIT",
  "kernel_version": "ACTUAL_FULL_KERNEL_ABI",
  "profiles": ["xiaomi_redmi-router-ax6000-stock"],
  "archive_sha256": "ACTUAL_ARCHIVE_64_HEX",
  "archive_size": 123,
  "profile_sha256": "ACTUAL_PROFILE_64_HEX",
  "public_key_sha256": "ACTUAL_PRODUCTION_PUBLIC_USIGN_KEY_64_HEX",
  "attestation_sha256": "ACTUAL_ARCHIVED_ax6000-imagebuilder.json_64_HEX",
  "verification_result_sha256": "ACTUAL_INDEPENDENT_VERIFY_ARCHIVE_RESULT_64_HEX"
}
```

For `612-recommended` and `612-latest`, the package manager is `apk`, the full ABI starts `6.12.`, and the exact reviewed layouts may include stock, mtkuboot, and ubootmod. The public usign key here authenticates the native generation/catalog approval; it is separate from APK repository PEM public keys inside the approved ImageBuilder. The utility relies on the pinned independent approval for signature, native bank, and source comparison; it does not repeat usign/APK signature verification or generate that approval itself. `verification_result_sha256` is an audit reference within the pinned approval, rather than permission to execute a supplied verifier.

The utility rechecks the archive/profile/public-key digests and generation/ABI/target. It requires the archive's `ax6000-imagebuilder.json` bytes to match the reviewed attestation, verifies every recorded context file, and requires kernel config, Image, DTB, target metadata, and package metadata evidence. Strict extraction rejects escapes, duplicate paths, special/setuid files, writes through link parents, and external links. Internal symlinks/hardlinks are accepted. Bounds are 16 GiB compressed archive, 24 GiB regular expanded files, and 200,000 members.

It rejects credential/private-key filenames, private-key text markers, and recognizable 104-byte usign Ed/BK secret-key structures even with misleading comments. Public usign keys and signatures remain accepted. This scan is an additional check, not a claim to detect arbitrary encoded secrets inside opaque package payloads; the independent approval covers the complete archive. No signing private key is an input or part of the Docker context.

## Validate, then explicitly build and load

```bash
cd /home/valuxin/dev/owrt/ax6000-asu
/usr/bin/python3 ops/builder_image.py \
  --archive /absolute/path/ACTUAL_IMAGEBUILDER.tar.zst \
  --archive-sha256 ACTUAL_ARCHIVE_64_HEX \
  --verification-receipt /absolute/path/REVIEWED_APPROVAL.json \
  --verification-receipt-sha256 INDEPENDENTLY_APPROVED_64_HEX \
  --profile /absolute/path/ACTUAL_profile.json \
  --public-key /absolute/path/repository.pub
```

After reviewing successful validation, repeat the same command with:

```text
--build-load --output /absolute/path/NEW_OPERATOR_OUTPUT_DIRECTORY
```

Run as the operator with access to the existing production Docker engine; do not use sudo or add the dedicated build account to its docker group. `--build-load` is a trusted manual operation that uses the existing rootful engine to construct the COPY-only image and launch bounded disposable clients. Public API/worker code must never invoke this utility or receive its production socket access.

The approved existing local tag is `ax6000-builder:20261012`, required to resolve to exactly:

```text
sha256:2398ea9311ca86441bd2c5756646caf2b5831f5d2c2a63c2d86373d5c527e653
```

The generated Dockerfile contains no `RUN`, `ADD`, or dependency setup. It copies only the verified ImageBuilder to `/builder` with UID/GID 1000, sets `USER 1000:1000`, clears the entrypoint, and defaults to `sleep 86400`. The server supplies its reviewed bounded flock/timeout holder command. The utility checks the base tag before/after construction, rejects base ONBUILD hooks, requires the final root filesystem layers to be exactly the base layers plus one COPY layer, and verifies the image's archive/cohort/build/proof/base/attestation/source labels and execution configuration. A disposable non-network probe checks UID 1000, writable `/builder`, the actual attestation SHA, and available working `flock`/`timeout` plus native tools. It does not execute IB makefiles.

Image export uses its immutable image ID. Import goes exclusively to:

```text
socket: /run/user/2000/docker.sock
engine: c592b58c-bc7e-40a0-91b5-29d5b29387a1
```

Because valuxin cannot traverse `/run/user/2000`, the utility launches a disposable client from the approved local base using explicit production `--host`, **without mounting the production socket into that client**. The client runs as `2000:2000`, drops every capability, enables no-new-privileges, has no network, uses a read-only root filesystem, and is capped at one CPU/2 GiB/no swap/128 tasks. Its only file/socket binds are `/usr/bin/docker` read-only, the dedicated rootless socket, and the exact exported tar read-only when loading. Every client call checks both expected rootless engine ID and the rootless security option before executing the requested explicit-socket Docker command. Ambient Docker host/context variables are cleared; no user's global Docker configuration is edited.

The loaded image ID/layers/labels and tool/attestation probe must match the constructed image. Production running container IDs are compared before/after. Success writes `load-receipt.json` with actual image ID, base/image layers, archive/approval/attestation hashes, loaded engine ID/socket, image tar SHA, and probe results. The receipt explicitly says `native_make_executed:false` and `catalog_promoted:false`. Failed operations retain their local staging/image artifacts for inspection and do not promote anything. The operator must still perform real `make info`, manifest/image assembly, layout checks, and the job's effective 4 CPU/CPU0–3/10 GiB/no-swap/2048-task verification before catalog promotion.

## Local tests

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s ops -p 'test_builder_image.py' -v
```

Tests use synthetic archives/keys/approval fixtures and mocked Docker commands. They verify no Docker call during validation, input mismatches, missing independent approval, cohort/kernel mismatch, archive attacks, private-key leaks, context drift, immutable layers/labels, numeric UID, explicit socket isolation, and ambient-context clearing. These tests do not establish that an actual ImageBuilder image has been built or loaded.
