# Offline catalog promotion

`promote.py` prepares a catalog and an immutable local snapshot tree. It does not start a service, contact either Docker engine, download packages, publish a site, sign anything, or flash a router. It never executes a tool from RAW, ImageBuilder or firmware inputs. Initial 6.6 promotion needs only OPKG/usign; new 6.12 cohorts require APK.

Run it only after independent verification of the actual native firmware, real ImageBuilder `make info`, manifest and image operations for every supported layout, and the [approved builder-image import](BUILDER-IMAGE.md). Unit fixtures do not meet these requirements. There are no fixture, skip-verification or force-approval switches.

## Required inputs

- A committed package-recipe checkout and its independently approved full Git commit. Its scripts, keys, profiles and files assets must be clean. The source profile must be under that checkout's `profiles/` directory. The production public keys must equal the committed keys.
- The actual native source directory at the profile's source commit, complete exported native RAW directory, and its generated profile. Native RAW profile bytes must equal the signed snapshot's profile. RAW import validation runs again.
- An actual restored signed snapshot directory. For 6.12 this is the existing restored envelope containing `snapshot-manifest.json`, its usign signature and `channel/`. The full existing channel verifier runs again, including APK signatures and regenerated native index identities. The immutable release pointer was checked when restoring the snapshot.
- For 6.6, either the newly signed ASU publication root or a normalized envelope with that tree under `channel/`. The signed manifest uses schema 1, `cohort: "66"`, `profile_id`, `build_id`, `kernel_version`, and `files` containing every channel file's relative path, size and SHA256. Only the envelope's own manifest/signature are excluded when supplied at the publication root. The promoter verifies the complete inventory, profile/lock, production key, and signed OPKG index/archive inventory.
- Independently reviewed native verification JSON plus its SHA256. This is the actual native verifier's `evidence.json`: `ok`, build/source/kernel identity, SDK context checksum, layout image hashes, installed package inventory and matching manifest hash, actual kernel hash, target metadata and partition geometry are checked. Installed defaults come from the actual native image manifest; the entire package bank is not made a default image.
- The exact ImageBuilder archive, its independently reviewed approval receipt and SHA256, and the actual builder load receipt and SHA256. Also supply the exported builder `image.tar`; its hash must match the load receipt. The immutable image ID, archive, source/build, attestation, rootless engine/socket and numeric user must agree. The package repository's actual `imagebuilder.verify_archive` runs again against native source and the complete native RAW package bank. No `make` is invoked by promotion.
- Independently reviewed real ImageBuilder smoke evidence and SHA256, as described below. The independent receipt digest is an authorization input; computing a digest from an invented receipt does not establish acceptance.
- Explicit trusted host usign path and SHA256. APK cohorts also require a trusted host APK path/SHA256 and the committed production APK public PEM. No private key is accepted.

Native core recipe roots, manager, vendor/ASU packages, their installed dependency closure and every native kmod remain protected. Supplemental packages may update approved user applications. Protected native archives must retain their exact native bytes. Canonical identities preserve actual package names and only their declared ABI suffixes in both APK and OPKG, including native suffixes such as `-0`. Packages without a declared suffix use an empty suffix. Tailscale remains outside mandatory/default images.

## Native root filesystem overlay

Standard ImageBuilder archives do not include the native source's `files/` directory. Promotion therefore adds a required, trusted `rootfs_overlay` to the catalog. Each exact path maps to `{content_base64, sha256, mode}`, with canonical base64, SHA256 and integer mode 0644 or 0755. The worker materializes these files through its own `FILES` directory, then writes the complete catalog identity to `etc/asu-cohort.json`. Client requests cannot supply or change this overlay.

The promoter first calls the committed recipe's repository renderer and ASU configurator in read-only check mode. It then reads actual native `source/files/` bytes and exact modes and requires matching `root.repository_files` or `root.optional_features.files` evidence in **every** inspected native layout. Only these fixed paths are copied:

- Common: `etc/asu-cohort.json`, `etc/uci-defaults/99-ax6000-asu`, `usr/sbin/ax6000-install-feed`.
- OPKG: `etc/opkg/distfeeds.conf`, plus the exact production fingerprint filename under `etc/opkg/keys/`.
- APK: `etc/apk/repositories.d/distfeeds.list`, `etc/apk/repositories.d/customfeeds.list`, `etc/apk/keys/repository-apk.pem`, `etc/ax6000/repository.pub`.

Installers and the ASU UCI-default script are 0755; other files are 0644. Files are capped at 64 KiB each and the overlay at 1 MiB. Links, evidence mismatches and additional inferred paths are forbidden. Other package-owned ASU/PBR/vendor files remain supplied by their verified packages.

For APK, the build-time `ax6000-apk-world-policy.json`, `scripts/ax6000-apk-world.py` and `include/rootfs.mk` hook must already belong to the verified ImageBuilder context. The promoter checks the source guard in read-only mode and requires native APK world/protected-list verification evidence. It never copies `/etc/apk/ax6000-protected.list` or the native image's world file: the retained ImageBuilder hook generates exact pins for each personalized root. Pre-catalog smoke may use the native four-field cohort file; the HTTP worker writes the complete eight-field identity after applying the trusted overlay.

APK catalogs additionally carry `apk_protected_roots`, the sorted canonical roots from the exact attested source `ax6000-apk-world-policy.json` after the read-only policy check. This differs from ASU's mandatory package list, which also includes UI/ASU applications. Installed native guard roots, essential packages, the manager and all installed kmods determine minimum protected pins; the guard calculates their actual dependency closure. OPKG catalogs omit `apk_protected_roots`. Neither format receives a static native world/protected-list overlay.

## Real ImageBuilder smoke receipt

Produce this receipt from actual command results and extracted image metadata, retaining the referenced files beside it. All artifact paths are relative to the receipt directory, without links or traversal. Values below describe the schema; they are not an approval.

```json
{
  "schema_version": 1,
  "kind": "ax6000-imagebuilder-smoke",
  "identity": {
    "build_id": "ACTUAL_BUILD_ID",
    "source_commit": "ACTUAL_SOURCE_COMMIT",
    "kernel_version": "ACTUAL_FULL_KERNEL_ABI",
    "architecture": "aarch64_cortex-a53",
    "target": "mediatek/filogic"
  },
  "archive_sha256": "ACTUAL_IB_ARCHIVE_SHA256",
  "attestation_sha256": "ACTUAL_ax6000-imagebuilder.json_SHA256",
  "snapshot_sha256": "ACTUAL_SIGNED_SNAPSHOT_MANIFEST_SHA256",
  "layouts": {
    "stock": {
      "exit_codes": {"info": 0, "manifest": 0, "image": 0},
      "info": {"path": "stock/info.txt", "size": 123, "sha256": "ACTUAL_SHA256"},
      "manifest": {"path": "stock/image.manifest", "size": 123, "sha256": "ACTUAL_SHA256"},
      "image": {"path": "stock/sysupgrade.bin", "size": 123, "sha256": "ACTUAL_SHA256"},
      "metadata": {"path": "stock/fwtool.json", "size": 123, "sha256": "ACTUAL_SHA256"},
      "kernel_sha256": "ACTUAL_UNCOMPRESSED_KERNEL_SHA256"
    }
  }
}
```

APK smoke `identity` additionally contains `"package_manager": "apk"`. OPKG identity omits that field, matching the existing ImageBuilder attestation. 6.6 requires stock only; 6.12 requires stock, mtkuboot and ubootmod. `info` must list the actual device, `manifest` uses actual `name - version` lines, `metadata` is the actual extracted fwtool JSON with exact layout/target, and the extracted uncompressed kernel must equal the independently verified native kernel. Every referenced artifact's bytes and size are checked. The default smoke must preserve native installed package names, use approved package versions and exclude Tailscale. A later personalized ASU Tailscale test remains a separate runtime acceptance test.

Native image metadata supplies the firmware version/revision; those must agree with the actual baked ImageBuilder version file. Layout support and partition bounds come from verified native evidence.

## Invocation

All paths and digests below must identify reviewed actual artifacts. Choose a fresh output directory. `--store` is the runtime's state directory, whose `immutable/` child is served read-only.

```bash
python3 ops/promote.py \
  --cohort 66 \
  --package-repository /trusted/package-recipe --recipe-commit "$RECIPE_COMMIT" \
  --source-profile /trusted/package-recipe/profiles/redmi-ax6000-new.json \
  --snapshot /verified/snapshot --source /actual/native/source --raw /actual/native/raw \
  --imagebuilder-archive /actual/imagebuilder.tar.zst \
  --native-evidence /verified/native/evidence.json --native-evidence-sha256 "$NATIVE_SHA" \
  --imagebuilder-evidence /verified/smoke/evidence.json --imagebuilder-evidence-sha256 "$SMOKE_SHA" \
  --builder-image-approval /verified/ib-approval.json --builder-image-approval-sha256 "$APPROVAL_SHA" \
  --builder-load-receipt /verified/load-receipt.json --builder-load-receipt-sha256 "$LOAD_SHA" \
  --builder-image-archive /verified/image.tar \
  --public-key /trusted/package-recipe/keys/repository.pub \
  --usign /trusted/tools/usign --usign-sha256 "$USIGN_SHA" \
  --site-url https://asu.ezon.by --store /dedicated/asu-state --output /fresh/promotion
```

For 6.12 use the exact cohort, corresponding source profile, and add `--apk /trusted/tools/apk --apk-sha256 "$APK_SHA" --apk-public-key /trusted/package-recipe/keys/repository-apk.pem`.

## Optional public APK userspace

No public package inventory is added by default. Supply `--mirror-registry`, its independently approved `--mirror-registry-sha256`, and one or more explicit `--public-package BASE_NAME` roots. The existing immutable mirror registry binds this exact signed snapshot to frozen original official indexes and public keys. Initial policy accepts only ImmortalWrt 25.12 aarch64 userspace feeds. No package archives are downloaded during promotion.

The promoter verifies the original indexes and official signatures using the mirror's shared decoder. It rejects canonical/actual-name collisions, protected providers, kernel/kmod packages, foreign managers and ambiguous ABI variants. A real read-only native APK recursive solver checks selected roots plus exact mandatory native pins against the complete native bank, supplemental index and tagged frozen public indexes. Nonzero errors, solver stderr, empty closures, missing pins, changed native versions and public origins for native collisions all fail. Only the accepted public dependency closure enters the catalog with tag `public` (matching the native router’s `@public` repositories) and exact actual names/versions. Original signed indexes remain unchanged.

The runtime registry uses container paths under `/indexes`. Add `--mirror-root /dedicated/asu-state/mirror` to rebase those paths locally for verification; `--mirror-prefix` changes the default `/indexes` prefix if the runtime mount differs. The original registry bytes and digest are not rewritten. Populate its local index/key files separately; promotion does not download or mutate that directory. Public URLs are `/immutable/<signed-snapshot-SHA>/public/<index-SHA>/<feed>/...` and are served by the separate bounded lazy mirror.

## Outputs and activation

After every check passes, the tool copies the exact signed tree to `STORE/immutable/<snapshot-SHA>/channel/`, retaining the signed envelope beside it. Files use exclusive creation and mode 0444; directories become 0555. Linux `renameat2(RENAME_NOREPLACE)` atomically installs each prepared directory. Existing snapshot/catalog destinations, links and changed source bytes are rejected; nothing is overwritten. Streaming copies bound memory use. A failed catalog install can leave a fully verified, unreferenced immutable snapshot for inspection.

The fresh output contains `catalog.json`, `catalog.sha256`, `feed-evidence.json` from actual repeated signature/bank checks, and `promotion.json`. The catalog's three promotion receipt hashes identify native evidence, real ImageBuilder smoke evidence, and the computed feed evidence. The final catalog is passed through the server's standard-library `Catalog.load` policy before persistent output. The audit records the independently reviewed builder approval/load receipt digests and recipe commit.

The tool prints the complete catalog SHA256 and always reports `service_activated: false`. An operator must separately review the result, expose the immutable tree/mirror, and configure the API process's existing `ASU_AX6000_CATALOG`, `ASU_AX6000_CATALOG_SHA256` and `ASU_AX6000_COHORT` deployment variables. Publication and actual HTTP/worker smoke acceptance remain separate steps.

## Tests

```bash
python3 -m unittest discover -s ops/tests -p test_promote.py -v
```

Tests use real host usign/APK signatures and index-only recursive solver fixtures, including APK's unsatisfied-query exit-zero behavior. They also cover readonly atomic copies, drift, symlinks, exclusive creation, independent receipt pins, native manifests and provider closure. They do not promote a catalog or activate a production service.
