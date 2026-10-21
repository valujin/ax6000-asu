# Operator context for hosted 612-latest

This candidate supports only producer `2a96db1b7163f37222a464b0795b8502e23b9e88`, source `a99b0888b88f134f56bcb2a7d93027b5d20638a9`, GitHub run `39646536507`, and native seed `19f59b194c1ea42734153adbf588af3de97081cfcc6aeb829447a17b60997228`. That run was still in progress when this candidate was prepared: no successful completion or native acceptance is implied. The loader requires actual successful run/steps and all new retained receipts before it can accept an envelope. Old EA/run `39611664646` evidence cannot substitute for the new producer. It never supplies a fabricated native source directory. Recommended remains the separate frozen EA producer; recommended and 6.6 continue to require `--source`.

The producer's Git tree was matched against the remote commit (`af22a88fd7a4059bf8972c1e59071d1912fbcbeb`). All Python recipe bytes equal EA; the shell build graph and resulting recipe seed changed. This does not prove the new functional Image is identical. The existing prior-Image witness and complete byte comparisons remain strict until separately reviewed actual facts permit a new acceptance contract. The old candidate patch/receipts and its nine original files are preserved under `TASK/hosted-latest-review/history-ea-candidate`; they are historical evidence, not acceptance for this producer.

Both operator commands choose exactly one `--source PATH` or `--hosted-context PATH --hosted-context-sha256 SHA256`. Every other existing signature, snapshot, tool, image approval/load, resource, lock and real smoke requirement remains applicable. These commands run from the reviewed source checkout. The existing deployed runtime image does not include the new hosted operator helpers; changing the source does not activate this mode on a running service.

Start from `ops/hosted-context-612-latest.template.json`. Its null fields are deliberately unusable. Fill and independently review only actual retained evidence, then pin the complete envelope SHA256. Every file record is `{ "path": "/canonical/absolute/file", "size": INTEGER, "sha256": "64 lower-case hex" }`. Paths must be regular files, with no symbolic link component. Tools additionally require `"authority": "independently-reviewed-host-tool"`; they must be executable and outside imported RAW. `fwtool` and `unsquashfs4` are required. If actual RAW `build.config` enables `CONFIG_LUCI_JSMIN=y`, the reviewed `jsmin` is required and must be a host x86_64 ELF. No RAW executable is selected as a tool.

Envelope roles:

| Field | Actual evidence |
| --- | --- |
| `identity` | Generated profile build ID, source commit, kernel version, architecture, target `mediatek/filogic`, package manager `apk` |
| `receipts.completion`, `api`, `download` | Canonical hosted completion, saved GitHub run/jobs, authenticated artifact download receipt, including retained original ZIPs |
| `receipts.native_evidence` | Original firmware-verification JSON from the authenticated diagnostic ZIP |
| `receipts.kernel_witness`, `native_acceptance`, `independent_verification` | Completed independent native/SDK/all-layout verification chain |
| `receipts.persisted_ib` | Completed persisted ImageBuilder verification with exact producer code blobs and explicit producer-side source validation |
| `receipts.overlay` | Seven-file all-three-image overlay evidence, with bytes, mode and digest |
| `native_inputs` | Actual RAW profile, lock, firmware manifest and build.config; each rechecked against the original authenticated ZIP member |
| `sdk_archive` | Actual SDK archive matching generated profile and kernel witness |
| `functional_kernel` | Retained decoded pre-initramfs Image, matching all three native layouts and IB context |
| `pbr_archives` | Both original locked author archives; archive hashes are compared to the actual release lock before deriving expected feature files |

The recipe must be an actual clean checkout at the fixed producer commit. Consumers recheck all ten recorded producer blobs against Git objects and checkout bytes, successful required steps, workflow source verification and failure propagation. The envelope SHA is an operator trust decision for saved evidence; this offline consumer does not contact GitHub or independently authenticate an arbitrary JSON success flag. Preserve the original API custody and independent review that establish its authority.

Acceptance must show that this producer performed source-dependent checks with its actual native source before packing and verification succeeded. This is labelled `producer-side-inferred-from-authenticated-successful-producer-export-and-verifier`. These source-dependent roles include native APK ELF/bundle/sstrip source transformations, native source Makefile/bundler preimages, original native public-key equality, full native context recomputation and original source preparation. The independent persisted receipt separately checks tracked source Makefile transformation/bundler hash, RAW APK source ELF hash, reviewed helpers, APK hook/policy, SDK kernel config and three-layout kernels/DTBs. The consumer reruns the normal frozen ImageBuilder verifier against the actual RAW APK bank, signed indexes/keys and every persisted context hash, then checks the seven retained prepared SDK contexts, prior OPKG kernel witness, functional Image/DTBs, APK policy/helper/hook provenance and recipe-rendered overlay. `independent_source_continuity` remains null and `local_native_source_claimed` remains false.

Hosted root inspection privately clones the exact frozen EA `inspect_root` function. Its code, defaults, closure and all other global bindings remain unchanged. Only the APK policy callback and a fresh feature-verification namespace are fixed to reviewed hosted implementations. The original module globals are untouched. Feature expectations come from the frozen recipe, locked author archives, actual RAW build config and separately reviewed host minifier. The normal APK database/control, package manifest, module/firmware byte, vermagic, key, translation and layout checks still run. The sole profile adjustment permits removing `tailscale` from `package_only` when the actual image manifest contains it; admission policy must separately establish it was installed originally.

Smoke and promotion must consume the same envelope SHA and exact source-validation scope. A generic earlier smoke receipt cannot satisfy hosted promotion. Future HTTP inspection calls `HostedContext.bind_catalog(path, sha256)` after native/IB verification, binding the actual promoted eight-field cohort identity; it does not alter the original native evidence.

No real hosted smoke, promotion, service activation or hardware boot is implied by the offline contract tests. Missing evidence, unknown future schemas and digest/mode/generation mismatches fail closed.

The separate local recommended path can optionally consume a successful V2
[native acceptance envelope](native-acceptance-recommended.md). Its root-enrolled
exact Image transition does not apply to latest and does not relax latest's
existing strict prior-Image witness.
