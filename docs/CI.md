# AX6000 continuous integration

The fork's workflows test its fixed AX6000 cohorts and operator tooling. They do
not promote a catalog, start a public API, contact a router, install a bootloader,
activate production Compose services or provision a build engine.

## Policy and operator tests

`test.yml` runs on main pushes and pull requests, and can be dispatched manually.
Set these repository **variables** to reviewed, published, full 40-character Git
commit SHAs before enabling the first run:

- `AX6000_PACKAGES_RECIPE_COMMIT`: `valujin/ax6000-packages` with the matching ASU,
  signature and native-export helpers.
- `AX6000_PACKAGES_612_RECIPE_COMMIT`: `valujin/ax6000-packages-6.12` with the APK
  implementation and independent host APK bootstrap.

The workflow rejects missing/non-SHA pins before checking out either repository.
The checkouts go to `.ci-recipes/packages` and `.ci-recipes/packages612`; neither
uses a moving branch. Missing required new helper files fail the job rather than
silently skipping their signature/package fixtures. The pins select **test source
code**, not approved firmware, a production catalog or an active ASU cohort.
Updating them is a reviewed operator change.

The job selects exact CPython 3.14.8, bootstraps uv 0.9.12 from a SHA256-checked
wheel into a temporary venv, then installs `uv.lock` with `--frozen`. It installs
build/SquashFS prerequisites only on the disposable GitHub-hosted runner. Host
compilation and test descendants use the package repository's verified hosted
resource scope; host APK is built with one compile job. Production hosts receive
no installation or configuration changes.

Automatic checks cover:

- Normal Ruff checks and formatting for `asu`/`tests`; error/undefined-name checks
  for the independently maintained operator modules.
- AX6000 policy, ASGI submit/poll, cohort separation, cache, engine isolation and
  rootfs-overlay tests.
- Operator promotion, real fixture signatures/ADB decoding/solver behavior,
  builder-image guards and smoke-runner command contracts, using independently
  built host APK 3.0.5 and official usign.
- Real pinned NGINX configuration/HTTP checks in isolated temporary containers:
  no production network attachment or host port.

Signing keys created by tests are disposable fixture keys. Neither production
signing secret is required by CI. The optional public-mirror network smoke is not
selected automatically; normal mirror tests use authenticated fixture indexes
and controlled HTTP responses. Reports retain the JUnit result and host-tool
bootstrap provenance for seven days.

The `legacy_tests` manual-dispatch input additionally runs the retained upstream
unit/fixture suite without `--runslow`. It does not start Podman or request an
OpenWrt One build. The removed automatic `podman.yml` depended on a deleted
Podman integration and a generic OpenWrt One request that this fork correctly
refuses. The original integration remains available in [upstream history](https://github.com/openwrt/asu/blob/77c5636045b0aed0762727363be105b2a5fa47fd/.github/workflows/podman.yml);
it is not a deployment or compatibility test for these AX6000 catalogs.

## Service-container smoke and optional publication

`publish.yml` builds and loads the service image on pushes/PRs. It uses the exact
CPython digest in `Containerfile`, frozen Python dependencies, and a dedicated
content-addressed BuildKit image. The builder has 2 GiB RAM with no swap and at
most half the runner's available CPUs (maximum two). The workflow inspects actual
Docker limits before building. It does not build firmware or an ImageBuilder.

The smoke test imports ASU, its dependencies and exactly the three packaged
operator modules, and compiles their Python source. It runs nonroot, read-only,
without capabilities, network or engine socket. It deliberately does not start
an API against invented production catalog identities.

Image publication is disabled by default. Only an explicit manual dispatch with
`publish_ghcr=true`, on `valujin/ax6000-asu`'s main branch, enables a separate job
with `packages: write`. That job consumes the **same tested image**, verifying its
archive checksum, image ID and source-commit label before pushing:

```text
ghcr.io/valujin/ax6000-asu:git-<full-source-commit>
```

There is no Docker Hub login, `openwrt/asu` tag, automatic registry upload or
moving `latest` tag. The registry's commit tag is a name, not a substitute for
immutable identity: deployment must record and use the actual registry digest.
A passing service-container CI check does not approve any firmware catalog or
replace a real matching ImageBuilder/default/requested-Tailscale/layout smoke.

## Reviewed bootstrap identities

Action refs were resolved against the official GitHub repositories on
2026-10-21; workflows use full commits:

| Action | Reviewed release | Commit |
|---|---|---|
| `actions/checkout` | v7.0.1 | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/setup-python` | v7.0.0 | `5fda3b95a4ea91299a34e894583c3862153e4b97` |
| `actions/upload-artifact` | v7.0.2 | `cf430e030ddbb5b0abf93d22962f4752f3646cd9` |
| `actions/download-artifact` | v8.0.2 | `9000827ccba6bdab643e8b6fd33ac0654aef8333` |

The independent APK bootstrap's source/wheel pins live in the reviewed 6.12
recipe. Official usign uses `f1f65026a94137c91b5466b149ef3ea3f20091e9`. The uv
wheel's SHA256 is
`822ea5a36e261f94a71c458ee79a8837d0a00d0b9b185a8f68fc0a9d452b1582`.
The container builder is
`moby/buildkit@sha256:cec9f139f45e93c5c69c60f8b07cfad9f43f4ef6b6a6cd917527fea5ff2e3dea`;
its digest was checked through the registry, and resource-driver options follow
[Docker's container-driver contract](https://docs.docker.com/build/builders/drivers/docker-container/).

See [origin activation](ORIGIN.md) and the [catalog contract](../deploy/CATALOG.md)
for the separate production acceptance and activation steps.
