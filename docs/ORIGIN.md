# Origin gateway and Nginx Proxy Manager

`deploy/frontend.yml` extends `deploy/compose.yml` in the same Compose project.
It creates a dedicated gateway and an optional immutable public APK mirror. It
does not edit Nginx Proxy Manager (NPM), its containers, its vhosts or host proxy
configuration. The gateway has no host port: NPM reaches the network alias
`ax6000-asu-front:8080` on the existing `nginx-proxy-manager_default` network.
The other gateway network is the project's existing private `api` network.

| Public path | Destination |
|---|---|
| `/66/api/v1/...`, `/66/json/v1/...`, `/66/store/...` | `api66:8000`, removing only `/66` |
| `/612/recommended/api/v1/...`, `/612/recommended/json/v1/...`, `/612/recommended/store/...` | `api612recommended:8000`, removing only `/612/recommended` |
| `/612/latest/api/v1/...`, `/612/latest/json/v1/...`, `/612/latest/store/...` | `api612latest:8000`, removing only `/612/latest` |
| `/immutable/<snapshot-sha256>/channel/<file>` | The operator-promoted read-only immutable tree |
| `/immutable/<snapshot-sha256>/public/<index-sha256>/<feed>/<file>` | `immutable_mirror:8000`, preserving the entire path |
| `/`, `/healthz`, cohort roots | Minimal gateway JSON; no web interface |

The LuCI server URL retains its cohort prefix, for example
`https://asu.ezon.by/612/recommended`. Relative `store` downloads and API redirects
remain under the same prefix. Docker DNS is resolved at request time; an absent
6.12 API or mirror does not prevent the gateway and ready 6.6 API from starting.
Gateway `/healthz` confirms only the gateway, not catalog or worker readiness.

## Promoted state and runtime

Use the previously reviewed `ASU_SERVICE_IMAGE` digest and dedicated
`ASU_STATE_DIR`. These mounts contain no signing keys or engine socket:

| Host input | Container path | Access |
|---|---|---|
| `$ASU_STATE_DIR/immutable` | `/immutable` in gateway | Read-only |
| `$ASU_STATE_DIR/mirror` | `/indexes` in mirror | Read-only |
| `$ASU_STATE_DIR/mirror-cache` | `/cache` in mirror | Read/write, bounded by the mirror |
| `$ASU_MIRROR_APK` | `/tools/apk` in mirror | Read-only, independently built host tool |

Promoted immutable directories must be readable/traversable by gateway UID 101
(e.g. public files 0644, directories 0755); do not put private files there. The
mirror runs as UID/GID 1000 and needs its own writable cache. Registry paths must
use container `/indexes/...` paths for frozen official indexes and PEM keys.
Pin its exact bytes in `ASU_MIRROR_REGISTRY_SHA256`, and the separately built host
APK binary in `ASU_MIRROR_APK_SHA256`. The registry is explicit operator trust
input; the public request cannot select an upstream URL or arbitrary filesystem
path. See [the mirror contract](../ops/MIRROR.md).

The final runtime image contains the operator modules `ops/immutable_mirror.py`,
`ops/promote.py`, and `ops/builder_image.py`, plus their native acceptance and
hosted context helpers `ops/hosted_context.py`, `ops/hosted_inspection.py`, and
`ops/native_acceptance.py`, under `/app/ops`, with `/app` on `PYTHONPATH`. The
standalone ImageBuilder smoke CLI is not bundled. No package installation is
needed at container startup. A host APK binary must also run against the pinned
runtime's libraries; a successful build in another image alone is insufficient evidence.
The separately reviewed APK 3.0.5 binary has been checked with `--version` inside
this exact pinned CPython runtime, nonroot with a read-only root and no network.

The mirror has a separate new project network for outbound HTTPS to its approved
official download origins. It does not join NPM's network or receive a Docker
socket. The API and Redis retain the private network from the base deployment.
Only the worker uses the dedicated rootless build engine described in the main
deployment contract.

## Activate cohorts in order

First complete catalog promotion, the real matching ImageBuilder smoke tests,
loaded-image/engine receipts, dedicated build-user setup and service-image
verification. A path or environment variable does not constitute promotion.
Compose interpolates required variables for the whole merged model, including
services not selected for startup; use the reviewed deployment environment and
start only explicit ready services.

From this repository, keep the same project name and both configuration files
for every operation:

```sh
docker compose -p ax6000-asu --env-file /path/to/reviewed-asu.env \
  -f deploy/compose.yml -f deploy/frontend.yml config

# Only after the 6.6 catalog, worker configuration and build engine are ready:
docker compose -p ax6000-asu --env-file /path/to/reviewed-asu.env \
  -f deploy/compose.yml -f deploy/frontend.yml \
  up -d redis api66 worker frontend
```

Do not start a 6.12 API against a placeholder catalog. After each real 6.12
catalog has been independently promoted, start its corresponding named API.
Activate the public mirror only after its registry, keys, exact frozen official
indexes, compatible host APK and cache permissions have been checked:

```sh
docker compose -p ax6000-asu --env-file /path/to/reviewed-asu.env \
  -f deploy/compose.yml -f deploy/frontend.yml --profile mirror \
  up -d immutable_mirror
```

The gateway has no `depends_on` relationship that starts an unready API or mirror.
Never run an unrestricted `up` to activate every cohort before promotion.

## Add a new NPM proxy host and origin certificate

Once the gateway and the first cohort pass internal HTTP tests, an operator must
create a **new** NPM proxy host in its existing UI:

- Domain: `asu.ezon.by`.
- Forward scheme: `http`.
- Forward hostname: `ax6000-asu-front`.
- Forward port: `8080`.
- Obtain/select an origin certificate that explicitly covers `asu.ezon.by`, then
  enable HTTPS for this new host. The current `*.dev.ezon.by` certificate does
  **not** cover `asu.ezon.by`.

Cloudflare DNS or its edge certificate does not provide a valid certificate for
the NPM origin. Keep authenticated origin TLS (`Full (strict)`); do not switch to
Flexible TLS to mask an origin certificate problem. Obtain the new certificate
through NPM using an appropriate supported challenge for the actual DNS/origin
setup. Do not replace an existing proxy host or certificate to add this service.
No NPM credentials or configuration API were available for automatic setup.

Keep proxy caching disabled for ASU API responses. Preserve the original Host,
HTTPS forwarding information and URI. The gateway supplies CORS, immutable
success headers and error cache policy itself; do not add a second CORS policy
in NPM. Global `store/` rewrites are unnecessary and would lose the cohort.

After NPM and origin TLS are ready, verify the public HTTPS certificate, a cohort
`json/v1/overview.json`, build submit/poll/download and an actual promoted
immutable URL. Perform a real ASU build and verify its package list, vendor stack,
kernel ABI and sysupgrade metadata before any router flashing. Existing API
loopback ports remain useful for internal acceptance, but they are not the NPM
forwarding target.

## Limits and checks

The gateway uses the pinned NGINX digest in `frontend.yml`, runs as 101:101 with
64 MiB RAM, 0.1 CPU, 64 PIDs, a read-only root, no capabilities and a bounded
`/tmp`. Only GET, HEAD, POST and OPTIONS are accepted; POST bodies are capped at
256 KiB. Metadata upstream timeouts are 15 seconds and streamed downloads use
180 seconds without proxy temporary files. Static paths cannot list directories
or follow symlinks; encoded separators, encoded dot segments and double-encoded
paths are rejected. Only the snapshot/channel and snapshot/public layouts above
are reachable.

CORS allows public LuCI origins (`*`) without credentials. The gateway hides
upstream CORS headers before adding its single policy, including errors and
OPTIONS. Only successful immutable responses receive the one-year immutable
cache policy; errors remain `no-store`.

Metadata admission is 5 requests/second with a burst of 20; build POSTs are
additionally limited to 2/minute with a burst of 2, and each proxy peer may hold
four active streams. By default NPM is one shared peer: the gateway intentionally
does not trust user-supplied `X-Forwarded-For` as a rate-limit identity. The ASU
application independently enforces its global bounded build queue and one worker.

Run the isolated real NGINX tests without connecting to production networks or
publishing a host port:

```sh
FRONTEND_TEST_DOCKER=1 python3 -m unittest discover \
  -s ops/tests -p test_frontend.py -v
```

They run the exact pinned image under the runtime limits, check `nginx -t`, then
probe only the test container's loopback interface with an in-process 6.6 echo
backend (the production routing stays identical). They cover JSON/CORS/method
limits, immutable bytes, traversal and symlink rejection, cache headers, prefix/query/store/redirect forwarding, missing
6.12 upstreams and the request-size cap. They do not deploy ASU or alter NPM. These
checks do not substitute for public HTTPS and real ImageBuilder acceptance.
