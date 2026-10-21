# Promoted catalog contract

A catalog is not self-authorizing. Production API processes require its complete
SHA256 from a separately reviewed deployment setting. Tests use explicit fake
catalogs and cannot activate them. Promotion must verify real native firmware,
matching standalone ImageBuilder, actual image assembly smoke, and all files of
the signed immutable package snapshot. No public request can change a catalog.

Each cohort has `/catalogs/COHORT.json` and a trusted worker
`/config/cohorts/COHORT.json` containing exactly the operational values:

```json
{"cohort":"612-recommended","catalog":"/catalogs/612-recommended.json","catalog_sha256":"ACTUAL_64_HEX","public_path":"/public/612-recommended"}
```

Catalog schema 1 fields:

- `cohort`: `66`, `612-recommended`, or `612-latest`.
- `package_manager`: `opkg` for 6.6; `apk` for both new 6.12 cohorts. No automatic cross-manager upgrade.
- `seed`: SHA256 native input identity known before SDK export.
- `build_id`, `source_commit`: exact promoted native generation and source.
- `snapshot_sha256`: SHA256 of the signed channel SNAPSHOTMANIFEST.
- `imagebuilder`: `archive_sha256` and `image` (locally loaded immutable Docker
  image ID `sha256:...`, or verified repository digest). Image must contain the
  matching complete `/builder` and numeric user `1000:1000`; no setup downloads execute.
- `firmware`: `version_number`, `version_code`, `target`, `architecture`, full
  OPKG `kernel_version` (`6.12.108~HASH-r1`), optional `kernel_release`.
- `profiles`: canonical profile keys, each with `supported_devices`,
  `mandatory_packages`, `default_packages`, `max_image_size` bytes. Defaults
  and mandatory packages exclude Tailscale. `66` supports stock only.
- `packages`: complete ABI-free target package-name to version inventory (up to
  50,000 indexed names, total catalog at most 8 MiB). Includes
  native frozen core and matching kmods plus the approved package refresh. A
  verified frozen official APK userspace index may extend this inventory; its
  incompatible dependency closures fail before any image is published.
- `package_identities`: required for both package managers; canonical name maps to `{name, abi,
  version, tag}` from verified immutable indexes. `name` is the exact actual APK
  name including the declared `abi` suffix; `version` matches `packages`, `tag`
  is empty for protected native packages. Actual names must be unambiguous.
- `package_specs`: optional trusted APK mapping, e.g. `foo` to
  `foo202610@public=1.2-r1`. Client package names cannot contain tags/pins.
  All APK packages use exact indexed actual names/tags/versions; mandatory packages and all kmods, and cannot select a public tag. Optional `protected_packages` extends
  this native protection to core libraries, routing and other operator choices.
  The matching ImageBuilder must pass real ABI/tag/version-formatting smoke.
- `repositories_conf`: OPKG signed HTTPS `src/gz` lines plus `option check_signature`,
  or APK HTTPS repository URLs with optional trusted `@tag`, one per line. All URLs include the signed
  snapshot manifest identity. Worker retains the native local signed package bank;
  no moving distribution feeds.
- `repository_keys`: complete usign public key files for OPKG, PEM public keys
  for APK; never private keys.
- `promotion`: `verified:true`, `native_evidence_sha256`,
  `imagebuilder_evidence_sha256`, `feed_evidence_sha256`. These bind independent
  actual evidence; the configured full catalog SHA256 remains the trust root.

Revision and overview responses carry `ax6000` with `schema_version`, `cohort`,
`package_manager`, `seed`, `build_id`, `catalog_sha256`, `snapshot_sha256`, `kernel_version`. The
client copies the selected target object into its build request. Requests also
include runtime-checked `installed_package_manager` and actual `installed_packages`; Tailscale is accepted only when both
requested and listed as already installed. The server cannot cryptographically
attest the remote device's installed list; this is an explicit user flow rule.

All cache identities include complete normalized request and catalog identity.
A worker refuses queued jobs after the corresponding approved catalog changes.
No unversioned moving snapshot is accepted. Do not copy a fixture into production.

`compose.yml` is intentionally incomplete until actual catalog/image/engine
values are supplied. It binds APIs to loopback and never starts the rootless
engine. `ASU_BUILD_UID`, `ASU_BUILD_GID`, `ASU_BUILD_LOCK_GID`, `ASU_ROOTLESS_SOCKET` and
`ASU_BUILD_ENGINE_ID` come from the reviewed rootless setup contract. Worker must
inherit the supplementary lock group explicitly. Dedicated build-user/service setup and origin TLS are separate operator
steps. A rootless engine socket confers that user's permissions; use a dedicated
user without production Docker group membership.

APIs and the worker join both the internal `api` network and the dedicated
noninternal `egress` bridge. The latter permits HTTPS index access and Docker
host-port publishing. Redis stays only on `api`; the frontend keeps its existing
`api` and NPM networks. API host ports remain bound to loopback.
The applied setup scripts, current host identity, mapped container-UID read ACL,
and actual PID1 hard-kill lock proof are documented in [ops/host](../ops/host/README.md).

The worker labels its build containers and removes only that label on its verified
dedicated rootless engine, during a short setup flock phase. It then releases its
setup lock. Container PID1 runs a bounded `timeout flock` holder on the **same
host lock inode** mounted read-only; no make command runs before a fresh random
ready token proves lock acquisition. Worker death does not release the container's
lock. PID1 timeout/container termination releases it. The operator must grant read
access only to the verified host UID mapping of container UID 1000 and verify
actual lock exclusion; no privilege or global file-mode relaxation is used.
Compose gives the worker 25 minutes for graceful shutdown of a 20-minute job.

Personalized output is assembled in a private temporary directory and atomically
published only after validation. Existing immutable output cannot be overwritten
with different bytes. Cache retention is at most 20 GiB per cohort and 7 days;
old private workspaces from hard job termination are removed before a new build.

Image certificate signing is not configured by this fork. `BUILD_KEY` is rejected
explicitly; the upstream host-bind path does not work across worker/daemon
namespaces. The client uses origin TLS, returned whole-file SHA256 and normal
router-side sysupgrade metadata validation. No private key is included in an
ImageBuilder/catalog, and no signature verification is bypassed.
# Native rootfs policy overlay

Every catalog requires `rootfs_overlay`, promoted from the independently reviewed
native source `files/` and verified against every native image's file evidence.
It maps each canonical relative path to `{content_base64, sha256, mode}`; modes
are integer `420` (0644) or `493` (0755). Content is canonical base64, limited to
64 KiB per file and 1 MiB total. The server requires exactly these paths:

- All managers: `etc/asu-cohort.json` (0644),
  `etc/uci-defaults/99-ax6000-asu` and `usr/sbin/ax6000-install-feed` (0755).
- OPKG: `etc/opkg/distfeeds.conf` and one
  `etc/opkg/keys/<16 lowercase hex fingerprint>` (0644).
- APK: `etc/apk/repositories.d/distfeeds.list`,
  `etc/apk/repositories.d/customfeeds.list`,
  `etc/apk/keys/repository-apk.pem`, `etc/ax6000/repository.pub` (0644).

Client requests cannot supply these files. The worker preserves approved modes
and replaces only `etc/asu-cohort.json` with the complete approved target identity.
Before publication, it extracts the generated sysupgrade artifact's actual SquashFS
root (tar for stock/mtkuboot; bounded static FIT references for ubootmod) inside the locked builder and checks each file's bytes and mode. SHA256
checks before and after inspection bind the inspected tar to the downloaded copy.

APK catalogs additionally require `apk_protected_roots`: sorted unique canonical
roots copied from the attested `ax6000-apk-world-policy.json`. The attested native
ImageBuilder rootfs hook generates `etc/apk/ax6000-protected.list` and `etc/apk/world`
for each personalized image. Those files are never copied from the native ROM.
Actual SquashFS checks require exact native pins for installed policy roots,
essential packages, the APK provider and all installed kmods. Every additional
protected pin must match an approved native manifest identity/version and appear
unchanged in world. Mandatory LuCI userspace does not become a core pin implicitly.

## Frozen public APK candidates

APK catalogs bind every approved package through two deduplicated tables:

```json
{
  "apk_repositories": {
    "native": {"url": "file:///builder/packages/packages.adb", "sha256": "SIGNED_INDEX_SHA256"},
    "public-packages": {"url": "https://asu.example/immutable/SNAPSHOT/public/INDEX/packages/packages.adb", "sha256": "SIGNED_INDEX_SHA256"}
  },
  "package_origins": {
    "example": {"repository": "public-packages", "filename": "example-1-r1.apk", "identity_sha256": "SIGNED_ADB_ROW_HASHES"}
  },
  "public_policy": {"mode": "candidates", "distribution": "immortalwrt", "tag": "public"}
}
```

The frozen public catalog selects exactly one distribution: `immortalwrt` or
`openwrt`. Promotion verifies every public repository belongs to that selection;
mixed distribution catalogs are rejected. Native origin and ABI protections
apply to both choices.

Repository IDs are `native`, `supplement`, and `public-<feed>` for the approved
base/luci/packages/routing/telephony/video feeds. Network indexes retain the
signed snapshot identity in their immutable URLs. `identity_sha256` is the actual
full SHA256 `hashes` value from the signed ADB package row, not a hash of JSON or
the truncated hash exposed by some APK package-info views. Every package has
exactly one approved origin. Protected native packages retain the native bank;
approved noncore refreshes may use the signed supplement.

`candidates` means eligible frozen metadata, with compatibility checked for each
request. It does not assert that all candidates can be installed together.
`validated-subset` retains the narrower promotion mode. Installed packages are
validated and included in request roots even if a client omits them from the
requested array; unavailable installed packages fail clearly. Installed Tailscale
is preserved, while adding Tailscale to a device without it remains disallowed.
The collective requested/installed/mandatory set is limited to 2048 packages.

Before `make manifest` can download or unpack package payloads, the worker injects
a trusted auxiliary make target. It includes the immutable native Makefile,
executes its unchanged `_check_keys` and index-only `package_reload`, then uses
the same root, cache, keys, repositories and APK executable. A real
`add --simulate --no-scripts --no-commit-hooks --usermode` transaction checks
conflicts; `query --recursive` alone ignores conflicts in the pinned APK version.
Structured repository queries then prove complete names, versions, ABI identities
and selected origins against SHA256/signature-verified frozen index rows. Any
cached payload accepted by the proof must reproduce its full approved ADB identity.
The native Makefile and frozen index bytes must remain unchanged.

Signed index sizes limit the selected closure to 2 GiB installed and 512 MiB of
archives before payload installation. Both the host output filesystem and actual
builder filesystem must have 20 GiB free beyond projected staging
(`2 * installed + 2 * archives + 1 GiB`); an initial host reserve check runs before
the job starts. The installed manifest must exactly equal the admitted closure.
Existing final manifest, actual image, overlay and partition-size checks still
run before publication. No native source, profile or seed is changed by this
temporary target, and no automatic ASU promotion timer is configured here.
