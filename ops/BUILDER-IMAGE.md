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

It rejects credential/private-key filenames, private-key text markers, and recognizable 104-byte usign Ed/BK secret-key structures even with misleading comments. Public usign keys and signatures remain accepted. This scan is an additional check, not a claim to detect arbitrary encoded secrets inside opaque package payloads; the independent approval covers the complete archive. Native and production signing private keys or other unapproved private credentials are never inputs or allowed in the Docker context.

The legacy approval field `private_keys_absent:true` means **native/production signing secrets and unapproved private credentials are absent**. It does not claim that no publicly distributed factory utility contains private-key-format data. The pinned upstream D-Link firmware factory tool contains five RSA private-key PEM blocks publicly shipped in its source header. Independent review established that all five complete blocks in the native/exported ELF are byte-identical to that public header. These publicly known vendor factory keys are recorded explicitly; no key bytes are reproduced in the approval or these docs.

To include that one exact upstream tool, a **new independently SHA-pinned approval receipt** must additionally contain this exact optional field:

```json
{
  "reviewed_public_vendor_tools": [
    {
      "path": "staging_dir/host/bin/.dlink-sge-image.bin",
      "sha256": "e1cc6b5b30c14f31017b4d2c460fe5642be18a6a36f50fb9d690711920ea1dbf",
      "size": 1857584,
      "classification": "public-upstream-vendor-factory-keys",
      "source_repository": "https://git.openwrt.org/project/firmware-utils.git",
      "source_commit": "5d1446bf57d6490573dc71f10c05e83b36d44374",
      "source_header_path": "src/dlink-sge-image.h",
      "source_header_sha256": "b792d24ab3bae14c39defc6e949caed42b2079cd1209266fe8460f87493869f6",
      "source_implementation_path": "src/dlink-sge-image.c",
      "source_implementation_sha256": "639dcee26d80c4dd1b9a60799b45a29a3b2cff081fb4f31b5a4ad608384cf112",
      "public_key_blocks": 5
    }
  ]
}
```

This is the sole permitted exception, bound to the [official firmware-utils repository](https://git.openwrt.org/project/firmware-utils.git) at the stated commit. The optional list defaults to empty and accepts at most one entry. Every field must match the compiled-in reviewed record exactly; unknown paths, tools, fields, provenance, hashes, sizes or classifications are rejected. The file must be present as a regular non-symlink x86-64 ELF with the exact full-file size and SHA before its known marker content is accepted. Appending a credential, changing one byte, moving the binary, or omitting approval fails. All other files still undergo the full filename/marker scan. The scan and successful load receipt both record any accepted exception. There is no command-line flag, environment override, wildcard or global marker suppression.

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

Image export uses the constructed immutable image ID. Before import, the saved tar is verified read-only: exactly one OCI manifest and one corresponding untagged Docker manifest, supported metadata/regular member paths, every `blobs/sha256` file's actual digest, matching descriptor sizes, config digest equal to the constructed classic image ID, and exact uncompressed layer digests/diffIDs. Import goes exclusively to:

```text
socket: /run/user/2000/docker.sock
engine: c592b58c-bc7e-40a0-91b5-29d5b29387a1
```

Because valuxin cannot traverse `/run/user/2000`, the utility launches a disposable client from the approved local base using explicit production `--host`, **without mounting the production socket into that client**. The client runs as `2000:2000`, drops every capability, enables no-new-privileges, has no network, uses a read-only root filesystem, and is capped at one CPU/2 GiB/no swap/128 tasks. Its only file/socket binds are `/usr/bin/docker` read-only, the dedicated rootless socket, and the exact exported tar read-only when loading. Every client call checks both expected rootless engine ID and the rootless security option before executing the requested explicit-socket Docker command. Ambient Docker host/context variables are cleared; no user's global Docker configuration is edited.

Classic Docker and Docker's containerd image store can report different immutable IDs for the same saved image. The classic ID is the config digest; the containerd store's inspect response uses the OCI manifest/index target digest ([exact Docker Engine source](https://github.com/moby/moby/blob/b26fb77/daemon/containerd/image_inspect.go#L85-L90)). The utility derives the **sole expected OCI manifest digest from the verified tar**, binding that manifest back to the constructed config and layers. It accepts only that verified manifest ID or the verified classic config ID from one clean `Loaded image ID: sha256:...` line. An arbitrary other ID, multiple loaded images, empty output, or an unpack-error line fails even when the Docker CLI exits zero. This is not an unrestricted ID-equality relaxation.

The loaded image's actual ID must equal the allowed reported ID; its layers, labels, numeric user/execution configuration and tool/attestation probe must still match the constructed image. The probe uses the actual rootless-store ID. Production running container IDs are compared before/after. Success writes `load-receipt.json` with `image_id` set to the **actual rootless image ID** for the catalog, plus `built_image_id`, `config_id`, `oci_manifest_id`, `oci_manifest_sha256`, `load_format`, and exact `load_stdout`. The receipt also records base/image layers, archive/approval/attestation hashes, loaded engine ID/socket, image tar SHA, and probe results. `load.stdout` is retained separately; a nonzero load also preserves `load.stderr`. The receipt explicitly says `native_make_executed:false` and `catalog_promoted:false`.

The normal CLI still requires a fresh output directory and never automatically resumes a failed build/load. Failed operations retain their local staging/image artifacts for operator inspection and do not promote anything. Existing exported bytes can be inspected with the read-only `saved_image_identity(archive, built_image_id, expected_layers)` helper and captured load output checked with `loaded_image_id(stdout, saved_identity)` during a separately reviewed operator recovery; neither helper performs a Docker operation. The operator must still perform real `make info`, manifest/image assembly, layout checks, and the job's effective 4 CPU/CPU0–3/10 GiB/no-swap/2048-task verification before catalog promotion.

## Local tests

```bash
PYTHONDONTWRITEBYTECODE=1 /usr/bin/python3 -m unittest discover -s ops -p 'test_builder_image.py' -v
```

Tests use synthetic archives/keys/approval fixtures and mocked Docker commands. They verify no Docker call during validation, input mismatches, missing independent approval, cohort/kernel mismatch, archive attacks, private-key leaks, context drift, immutable layers/labels, numeric UID, explicit socket isolation, and ambient-context clearing. Transport fixtures prove both classic/config and containerd/manifest IDs bind to the same verified saved bytes; changed blobs, config/layers, multiple manifests, wrong descriptor sizes, duplicate/unsafe members, unknown loaded IDs and unpack-error output are rejected. Vendor-tool tests cover exact approved bytes, missing/changed provenance, arbitrary tools, secret appends, unrelated marker-bearing files, forbidden private filenames, and unchanged receipt-digest rejection. An additional read-only test verifies the actual reviewed ELF when supplied via `BUILDER_TEST_PUBLIC_VENDOR_TOOL`; it skips only when those external local bytes are unavailable. These tests do not establish that an actual ImageBuilder image has been built or loaded.
