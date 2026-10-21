# Immutable public APK mirror

`immutable_mirror.py` is an independent, engine-free FastAPI application. It does
not import ASU, use Docker, access a socket, sign repositories, execute target
binaries, install packages, extract payloads or run package scripts. Its only
external executable is a separately provisioned, SHA256-pinned **host** APK3
binary. It verifies already frozen official indexes before accepting requests.

The mirror preserves original official index bytes and signatures. A new public
index promotion always adds a different index SHA256 segment, even when the
native firmware snapshot has not changed:

```text
/immutable/<native-signed-snapshot-manifest-sha256>/public/<official-index-sha256>/<feed>/packages.adb
/immutable/<native-signed-snapshot-manifest-sha256>/public/<official-index-sha256>/<feed>/<actual-name>-<version>.apk
```

The native snapshot's other restored files remain in the frontend's separately
verified static tree. Route the `/public/` mirror pattern to this service before
the broader static `/immutable/` location. Neither the mirror nor its clients
choose a snapshot directory or arbitrary origin URL at request time.

## Operator registry

Mount the registry, official PEM keys, frozen ADB files and trusted host APK
read-only. Pin the registry's exact byte SHA256 in service configuration; changing
the registry requires an operator-reviewed hash update and service restart. The
operator/promoter first verifies and restores the native signed snapshot and
supplies its actual signed-manifest SHA256. A registry is **trusted operator
input**, not an unauthenticated browser request or a claim that this service
verified the native snapshot's outer signature.

```json
{
  "schema_version": 1,
  "snapshots": [
    {
      "snapshot_sha256": "<64 lowercase hex: native signed snapshot manifest>",
      "repositories": [
        {
          "feed": "packages",
          "index_sha256": "<64 lowercase hex: exact official packages.adb bytes>",
          "index_path": "/indexes/immortalwrt/packages/packages.adb",
          "distribution": "immortalwrt",
          "key_path": "/keys/immortalwrt-25.12.pem",
          "key_sha256": "c0da9b5747f3fb16ea64fa37acda4df3723ac22ec30ca0dc6f5c89efc0161f1f",
          "base_url": "https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/"
        }
      ]
    }
  ]
}
```

Replace placeholders with independently checked hashes; they are not accepted
literally. Supported feeds are `base`, `luci`, `packages`, `routing`, `telephony`
and `video`. Origins must be the distribution's exact HTTPS
`downloads.immortalwrt.org` or `downloads.openwrt.org` host, on the 25.12 release
or `packages-25.12` branch, under `aarch64_cortex-a53`. Userinfo, alternate ports,
queries, fragments, target/core/kmod paths, other architectures and custom
`pkgname-spec` layouts are refused. Indexed packages must have the target arch
or `noarch`. The PEM trust anchor is explicitly selected and hashed by the
operator; do not source it from an untrusted registry or router request.

Use the same distribution as the native build. OpenWrt is a separately selected
alternative, not an automatic fallback to fill missing ImmortalWrt packages.
APK format, architecture and musl compatibility do not guarantee matching
features, ABI-suffixed dependencies or vendor/kernel compatibility.

The offline promoter may import stdlib-only `Decoder(apk_path, apk_sha256)` and
`Repository(record, decoder)`. A verified repository exposes `.data` (original
index bytes), `.rows` (actual `name-version.apk` to full native index record),
`.sha`, `.feed` and `.base`. FastAPI/httpx imports are deferred until
`create_app()` is called. Do not modify or reconstruct the original official
signed index to create a package allowlist.

## Service entry point

The service needs the repository's already pinned FastAPI/httpx/uvicorn runtime.
The default ASU runtime image currently packages only `asu`; the deployment owner
must also include `ops/immutable_mirror.py` in the mirror image. No new host
installation is required.

```sh
export AX6000_MIRROR_REGISTRY=/indexes/registry.json
export AX6000_MIRROR_REGISTRY_SHA256=<reviewed-registry-byte-sha256>
export AX6000_MIRROR_APK=/tools/apk
export AX6000_MIRROR_APK_SHA256=<independently-built-host-binary-sha256>
export AX6000_MIRROR_CACHE=/var/cache/ax6000-public-apk

uvicorn ops.immutable_mirror:create_from_env --factory --host 0.0.0.0 --port 8081 --workers 1
```

For activation checking without starting an HTTP server:

```sh
python ops/immutable_mirror.py check \
  --registry /indexes/registry.json --registry-sha256 <reviewed-registry-sha256> \
  --apk /tools/apk --apk-sha256 <reviewed-host-apk-sha256> \
  --cache /var/cache/ax6000-public-apk
```

Use a dedicated nonroot UID and cache, a read-only container root, no capabilities,
no-new-privileges, no secrets and no engine socket. Provide a bounded temporary
filesystem for decoder scratch data. The cache directory is the only persistent
writable mount. Use **one process per cache**; an exclusive cache lock rejects
another worker using that directory. Apply container memory/PID limits and a
frontend request/concurrency limit. The application itself bounds active APK
fetch/verification operations to two, each package to 256 MiB, cached payloads
plus reserved download bytes to 2 GiB, upstream read/connect timeouts and total
stream time, and native decoder output/runtime. Process/container quotas remain
the outer bound for temporary decoder files and Python/tool memory.

## Verification and cache behavior

Activation checks the host tool's file SHA256, the operator registry hash, each
index's exact byte hash and public PEM hash, and each official index signature
with an isolated directory containing only that repository's configured key.
There is no `--allow-untrusted` on index authentication. It retains verified
index bytes in memory, so later changes to the mounted source file cannot change
an already activated URL's response.

Only exact filenames derived from authenticated `name` and `version` fields can
trigger a download. No client-provided URL is accepted. HTTPS redirects are not
followed, proxy environment variables are ignored, compression is refused and
the response must match the signed index's archive length. The payload is streamed
to a mode-0600 file on the cache filesystem, then checked with:

1. Native `apk --allow-untrusted verify` for archive/payload integrity. Official
   OpenWrt/ImmortalWrt APKs are commonly unsigned individually.
2. Native `apk mkndx --allow-untrusted --hash sha256` over that single downloaded
   archive, followed by complete decoded record equality against the original
   authenticated official row, including native identity and archive length.
3. Whole-file SHA256 for subsequent local cache corruption detection.

The temporary file becomes visible only after verification, flush/fsync and an
atomic rename. A failed signature, length, native metadata/identity comparison,
redirect, timeout or corrupt APK yields HTTP 502 and no new cached payload.
Unknown path/snapshot/index/package names yield 404 without contacting an origin.
Known objects use immutable cache headers and strong ETags. Only payload files
are evicted by LRU; frozen operator indexes and keys are never deleted. Cached
files recovered after restart are reverified against the trusted row before use.
Open response streams retain a lease so LRU cannot remove their backing file.

Do not compare the APK's embedded 40-hex info identity, the signed index's
64-hex native identity and the complete archive's SHA256 as interchangeable
values. Re-indexing with the pinned tool makes the native comparison meaningful.

Cold-cache availability still depends on the approved upstream retaining that
exact indexed archive. If an upstream removes or replaces it, the immutable URL
fails closed instead of serving another package. To keep selected packages
available independently of upstream retention, warm and retain those exact
objects or use a separately managed permanent object store. This bounded lazy
cache intentionally does not download or promise permanent storage of every APK.

## ASU catalog boundary

Mirroring a signed full public index does not authorize every package in an ASU
request. The promoter/server must expose only explicitly approved public package
identities and accepted dependency closure, retain exact native/core/vendor/kernel
pins, reject actual/canonical name and provider collisions, and reject foreign
kernel dependencies. Preserve actual ABI-suffixed names for APK, stripping only
the declared `openwrt:abiversion=` suffix when producing canonical ASU catalog
names. Public repo tags are opt-in solver eligibility, not a core-package firewall.

The pinned APK3 `query --recursive --from repositories --format json` solver can
check frozen indexes without downloading payloads. Create an isolated empty root
with empty `lib/apk/db/installed` and `etc/apk/world`, plus target `etc/apk/arch`;
use a local repositories file and isolated trusted keys. Include all exact native
pins and explicit `package@public` constraints. Request `repositories` and
`download-url` alongside package metadata to verify protected origin selection.
APK 3.0.5 has two relevant quirks: an unsatisfiable recursive query may return
exit 0 with an empty result and an error on stderr; the declared `hash` query
field is unimplemented and returns failure. Require successful status, clean
stderr and complete expected constraints, and bind selected identities to the
already verified repository rows by their selected repository paths. Do not use
exit status or version equality alone as proof of native provenance.

## Tests

`ops/tests/test_immutable_mirror.py` uses FastAPI's ASGI TestClient, mocked HTTP,
real host APK3 metadata/signatures and disposable test keys. Set
`MIRROR_TEST_APK` to the independent trusted host APK binary. Tests cover strict
activation hashes and official-key signature checks, identity/architecture/path
rejection, malformed ADB/registry, corruption and size limits, redirect refusal,
lazy fetch/cache behavior, restart-safe layout, cache ownership, LRU, tamper
refetch and the two-download concurrency bound.

An optional real-network smoke test downloads **one small official APK only**:
set `MIRROR_OFFICIAL_SMOKE` to the existing pinned research evidence directory
containing `immortalwrt-packages.adb` and `keys/immortalwrt-25.12.pem`. It verifies
the real official index/signature, serves its exact bytes through ASGI and fetches
`6in4-29.apk` once through the lazy verifier/cache. All test databases, generated
private keys and caches are temporary and never become production trust roots.
