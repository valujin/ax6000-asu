# Hosted latest ASU context implementation plan

> Execution: inline implementation with independent peer review before root integration.

Goal: accept authenticated hosted-native evidence for 612-latest in operator smoke and promotion without a fabricated native source tree.

Architecture: one explicit typed hosted context shared by both consumers. Existing --source behavior remains unchanged. Producer-side original-source transformations are authenticated through frozen producer code and completed GitHub steps; persisted artifacts, context, package banks, keys, APK guard and all-three-image overlays are checked independently. Independent original source continuity stays null.

Approved spec: root's latest-only hosted-context design in this task, including authenticated producer verifier invocation, independent persisted artifact checks, exact overlay rendering and strict missing-evidence rejection.

Constraints: isolated worktree at c0fee57; no active source edits, merges, pushes, deployment, heavy jobs, source proxies, imported RAW executable use or invented acceptance hashes.

Follow-up: bind only latest producer `2a96db1b7163f37222a464b0795b8502e23b9e88`,
run `39646536507`, seed `19f59b194c1ea42734153adbf588af3de97081cfcc6aeb829447a17b60997228`.
The run was in progress during preparation. Old EA candidate files/receipts are
preserved separately; Python recipe bytes equal EA, but new successful receipts
and strict actual Image facts are still mandatory. Optional local recommended
V2 acceptance remains pinned to the separate EA producer and exact root-enrolled
context; it never supplies an exception to latest or 6.6.

Files: new ops/hosted_context.py and ops/tests/test_hosted_context.py; modify ops/promote.py and ops/smoke_imagebuilder.py; operator documentation only. Report any copied runtime module change to root.

- [x] Define the pinned hosted envelope and strict record/mode/identity bounds. Write failing tests for missing evidence and corruption of API, artifact, witness, overlay, tools and recipe.
- [x] Implement shared validation of exact latest identity, authenticated completion/code-call proof, native RAW/persisted IB context, actual SDK/kernel witness, seven-file overlay and trusted tools. Keep producer and independent scopes separate.
- [x] Add mutually exclusive local-source / latest-hosted CLI paths to smoke and promotion. Reuse normal bank/index/context verification and independently reconstruct source-derived policy checks from typed artifacts.
- [ ] Verify unchanged local-source contracts, run focused tests with no host dependency changes or real build execution, and obtain independent peer review. Leave branch unmerged/unpushed.

Review focus: all receipts must bind the same generated profile and archive; an API success flag alone is insufficient; recipe-derived expected bytes must differ from observed bytes; tool paths are independently pinned and never inferred from imported RAW; no successful hosted receipt implies local source continuity.
