# Optional recommended native acceptance envelope

This operator helper binds the separate frozen EA recommended producer. The actual
R5 packaging/export process `b0b3007b…f870e` exited 0 without OOM; that observation
alone does not claim independent native acceptance, ImageBuilder smoke, promotion
or hardware boot. These still require their real reviewed receipts. Earlier
attempts remain preserved: R3 completed world and ImageBuilder but exited 1 during
export; R4 emitted RAW and then failed its postguard. Neither is relabelled as a
successful process. R5 repackaged a pristine ImageBuilder before export; it did
not rebuild world or the kernel.

`ops/promote.py` accepts optional `--native-acceptance PATH` together with
`--native-acceptance-sha256 SHA256`. Both flags are required together, exclusively
with actual `--source` and cohort `612-recommended`; 6.6 and latest reject them.
Omitting both retains existing operator behavior and catalog fields unchanged.
The SHA is an explicit operator approval of a completed independent native V2
receipt, not an automatically trusted success flag or a network URL.

The required successful envelope uses schema 2 and kind
`ax6000-native-completion-acceptance-v2`, and must bind frozen producer
`ea6de11283a6d83728e50b4b9ced214761ecc1c0`, source
`ae65e1de69971b5a2e3cf7e39390ee93f274d488`, seed
`ff3a83d4df51fbe2d952538fa020f71bbae650bc88fe636ee273f7828e3022ad`, the actual
generated build ID and exact ABI `6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1`.
It requires zero verifier exit/no OOM, all three layouts, exact underlying native
evidence and four RAW files (`profile.json`, `lock.json`, `firmware-manifest.json`,
`build.config`) through `native_input_records`, including their canonical absolute
paths and current hashes/sizes. The three named `native_inputs` records remain
required as well. The status schema and kind remain unchanged; the independently
reviewed V4 verifier must emit `producer_chain.kind` equal to
`ax6000-staged-native-producer-chain-v1` with exactly these stages:

- `world_and_imagebuilder`: actual R3 producer `9ec62627…73e19`, process exit 1,
  successful steps exactly `world`, `imagebuilder`, and four retained receipts:
  `started.json`, `after-world.json`, `after-imagebuilder.json`, `result.json`.
- `export`: a distinct reviewed exporter matching `final_producer_id`, process
  exit 0, successful steps exactly `imagebuilder-package`, `export`, and four
  retained receipts: `started.json`, `after-imagebuilder.json`, `after-export.json`,
  `result.json`. Its result records `repackaged_imagebuilder:true`; it makes no
  claim that world ran in that process.

`failed_processes` is an ordered list of exact records
`{producer_id, process_exit_code, inspect:{path, sha256, size}}`. Each inspection
must identify that process, be terminal (`exited`, nonrunning, no OOM), and have
the matching positive integer exit code. `failed_producer_ids` must project this
complete ordered history with unique IDs. The enrolled first two historical
failures remain its prefix; the reviewed V4 receipt authenticates the later
actual attempts. This consumer does not duplicate every transient ID or impose
a fixed number of failed processes. Every inspection file is checked against
current bytes and `native_input_records`, alongside stage references.
The world/IB process must appear as an exit-1 failure, while the final exporter
must be distinct from every failed process. Final exit 0 describes that exporter;
it does not imply that world or the original ImageBuilder build ran there.
R3's manifest is pinned to SHA256
`3cf19fdab1809b3ce5e6f9b563f0194e873d3550ab450a784c87131010d72a9d`
(size 13,602). Each stage's manifest and runtime receipt is a full regular-file
reference `{path, sha256, size}`; all ten stage files must match current bytes
and `native_input_records`, with no duplicate paths, including terminal inspections. Different stage runner
paths are supported explicitly. The final RAW path is derived from the reviewed
status and must agree with the explicit promotion input. Historical manifests may
refer to earlier RAW/SDK/ImageBuilder artifacts; their retained hashes remain
historical evidence, while final RAW metadata identifies the current augmented
SDK and ImageBuilder archives. The approved status SHA binds the exporter's
actual identity and manifest; only the independent verifier checks the exact
reviewed producer plan, mount and capability evidence. The downstream helper
never executes imported tools or substitutes runner paths.
All strict context claims remain required.
Its explicit regular-file references
are checked against these immutable operator-approved identities:

| Role | SHA256 |
| --- | --- |
| `accepted_context` | `2d7dbf000444728dedd334a432445cf8aece08b2944e6d28e172d823490f8d15` |
| `root_enrollment` | `c0b5ac9ba485f617662221dec2e9829772c4602f9091e0cda4297071d493cdea` |
| `kernel_image_transition` | `5f958f7cb6569f34ef3f02602c86e00c918ed8b53db1f80800d8e4d17b68a01a` |

The original context (`cddaaf65…fd87c`) and old Image (`ac19e2c5…86d8f`) remain
historical evidence. Only `KDIR/Image` changes in the accepted strict context;
its complete new identity is SHA256
`5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611`, size
14,661,640 bytes. The promoter hashes the entire actual source Image and four
unchanged ABI files, and requires all three decoded native layout kernels and
the native sysupgrade-input record to match that complete new Image.

The receipt must state `strict_accepted_context_unchanged:true`,
`prior_native_image_byte_identical:false`, and
`prior_native_abi_context_byte_identical:true`, with exact before/after strict
context maps. The ambiguous `strict_base_context_unchanged` field is rejected.
No note masking, Build ID normalization, byte rewriting, old-Image restoration or
generic exception is performed. Missing/proposal/failure receipts fail closed.

All normal source Git, signature, SDK/IB/native bank, rootfs overlay, trusted-tool,
ImageBuilder smoke and loaded-image checks remain mandatory. Successful optional
verification adds the envelope SHA to the catalog's `promotion` object and its
full reference summary to feed evidence and the promotion audit; the final catalog
SHA binds them. It changes no runtime request handlers or service configuration.
These source-only helpers are not automatically installed into a deployed image.

Use the real reviewed status receipt only after native completion and independent
verification. Supplying the enrolled context file itself as `--native-acceptance`
cannot authorize a build. Unit fixtures test guards with synthetic constants and
are never accepted production evidence.
