"""Explicit operator-only hosted LATEST context; never a native source surrogate.

Original source transformations are producer-side evidence. Retained artifacts,
kernel/context, policy, keys and overlays are independently checked by consumers.
All paths/digests below come from one separately reviewed envelope, never HTTP.
"""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import zipfile

PRODUCER = '2a96db1b7163f37222a464b0795b8502e23b9e88'
SOURCE = 'a99b0888b88f134f56bcb2a7d93027b5d20638a9'
RUN = 39646536507
SEED = '19f59b194c1ea42734153adbf588af3de97081cfcc6aeb829447a17b60997228'
OLD_CONTEXT = '24980eeed1f05bea99abd80cf0b544d2a49742de1837a100394d66c3ad0893a8'
SHA = re.compile('[0-9a-f]{64}')
LAYOUTS = {'stock', 'mtkuboot', 'ubootmod'}
STEPS = {'Build firmware, SDK and kernel modules',
         'Independently verify native images and matching SDK context',
         'Upload complete firmware and SDK artifacts', 'Upload build diagnostics'}
CODE = {'.github/workflows/firmware.yml', 'scripts/build-firmware.sh',
        'scripts/prepare-firmware.py', 'scripts/imagebuilder.py',
        'scripts/host_apk_bundle.py', 'scripts/verify-firmware.py',
        'scripts/apk_world.py', 'scripts/package_format.py',
        'scripts/ax6000-ib-abi.py', 'scripts/asu_client.py'}
CONTEXTS = {'.config', '.config.set', '.vermagic', 'Module.symvers',
            'modules.builtin.modinfo', 'include/config/kernel.release',
            'include/generated/autoconf.h'}
OVERLAY = {'etc/asu-cohort.json': 0o644, 'etc/uci-defaults/99-ax6000-asu': 0o755,
           'usr/sbin/ax6000-install-feed': 0o755,
           'etc/apk/repositories.d/distfeeds.list': 0o644,
           'etc/apk/repositories.d/customfeeds.list': 0o644,
           'etc/apk/keys/repository-apk.pem': 0o644, 'etc/ax6000/repository.pub': 0o644}
CALLGRAPH = ['build-firmware.sh successful final --phase export',
    'prepare-firmware.export -> export_imagebuilder(generated, actual native source)',
    'export_imagebuilder -> imagebuilder.export_archive', 'APK export_archive -> export_apk_archive',
    'export_apk_archive -> verify_apk_tree(source=actual native source,native_packages=actual source APK bank)',
    'verify_apk_tree success precedes _pack_imagebuilder; returned archive SHA/size binds generated profile and RAW manifest',
    'independent verifier shell success -> inspect_sdk actual source/SDK comparisons and native APK source-transform validation']


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def checked_record(record, cap=32 * 1024**2):
    need(isinstance(record, dict) and isinstance(record.get('path'), str), 'Missing hosted input record')
    path = Path(record['path'])
    need(path.is_absolute() and str(path) == record['path'] and '..' not in path.parts
         and path.is_file() and not any(p.is_symlink() for p in (path, *path.parents)),
         'Hosted input must be a canonical regular file')
    need(type(record.get('size')) is int and 0 <= record['size'] <= cap
         and path.stat().st_size == record['size']
         and isinstance(record.get('sha256'), str) and SHA.fullmatch(record['sha256'])
         and sha(path) == record['sha256'], 'Hosted input size/SHA differs: ' + str(path))
    return path


def json_file(path):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            need(key not in result, 'Duplicate hosted JSON field')
            result[key] = value
        return result
    def constant(_):
        raise ValueError('Nonfinite hosted JSON')
    data = json.loads(Path(path).read_bytes(), object_pairs_hook=unique, parse_constant=constant)
    need(isinstance(data, dict), 'Hosted metadata must be an object')
    return data


def artifact_member(artifact, name, record):
    """Bind retained metadata to an exact member of the API-digest ZIP."""
    path = checked_record(record)
    with zipfile.ZipFile(artifact['zip']['path']) as archive:
        members = archive.infolist()
        need(len(members) <= 2500 and sum(item.filename == name for item in members) == 1,
             'Hosted artifact metadata member is absent or ambiguous')
        info = archive.getinfo(name)
        need(not info.is_dir() and not info.flag_bits & 1 and info.file_size == record['size']
             and info.file_size <= 32 * 1024**2, 'Hosted artifact metadata member size/type differs')
        with archive.open(info) as stream:
            data = stream.read(record['size'] + 1)
        need(data == path.read_bytes(), 'Retained hosted metadata differs from authenticated artifact bytes')


def module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def require_latest(profile):
    need(profile.get('channel') == 'latest' and profile.get('package_manager') == 'apk'
         and profile.get('asu', {}).get('cohort') == '612-latest'
         and profile.get('asu', {}).get('seed') == SEED
         and profile.get('firmware', {}).get('commit') == SOURCE,
         'Hosted context is restricted to the reviewed APK 612-latest producer')


def identity(profile):
    f = profile['firmware']
    return {'build_id': profile['build_id'], 'source_commit': f['commit'],
            'kernel_version': f['kernel_version'], 'architecture': f['architecture'],
            'target': 'mediatek/filogic', 'package_manager': 'apk'}


def verify_producer(completion, api, download, persisted, recipe):
    """Authenticated saved API/code chain, not an unauthenticated pass flag."""
    need(completion.get('kind') == 'ax6000-hosted-native-completion-v1'
         and completion.get('ok') is True and completion.get('run_id') == RUN
         and completion.get('head_sha') == PRODUCER and completion.get('run_status') == 'completed'
         and completion.get('run_conclusion') == 'success'
         and completion.get('local_container_exit_claimed') is False,
         'Hosted completion identity/outcome differs')
    run, jobs = api['run'], api['jobs']['jobs']
    need(run == download['run'] and api['jobs'] == download['jobs'], 'Saved hosted API receipts disagree')
    need(run.get('id') == RUN and run.get('head_sha') == PRODUCER
         and run.get('repository', {}).get('full_name') == 'valujin/ax6000-packages-6.12'
         and run.get('head_repository', {}).get('full_name') == 'valujin/ax6000-packages-6.12'
         and run.get('path') == '.github/workflows/firmware.yml'
         and run.get('head_branch') == 'main' and run.get('event') == 'workflow_dispatch'
         and run.get('status') == 'completed' and run.get('conclusion') == 'success'
         and run.get('run_attempt') == completion.get('run_attempt'), 'Hosted API source/run differs')
    need(jobs and all(j.get('status') == 'completed' and j.get('conclusion') == 'success' for j in jobs),
         'Hosted job failed or is incomplete')
    required = {}
    for name in STEPS:
        matches = [(j, s) for j in jobs for s in j['steps'] if s.get('name') == name]
        need(len(matches) == 1, 'Hosted required step absent/ambiguous: ' + name)
        job, step = matches[0]
        need(step.get('status') == 'completed' and step.get('conclusion') == 'success',
             'Hosted required step did not succeed: ' + name)
        required[name] = {'job_id': job['id'], **step}
    need(completion['required_steps'] == required, 'Completion step receipt differs from API')
    source = persisted['producer_side_source_validation']
    need(source.get('classification') == 'producer-side-inferred-from-pinned-code-and-authenticated-successful-steps'
         and source.get('independent_full_native_source_revalidation') is False,
         'Hosted source-transform scope must be producer-side only')
    need(source.get('required_steps') == required and set(source.get('code_blobs', {})) == CODE,
         'Producer source call graph lacks exact code/step coverage')
    need(source.get('callgraph') == CALLGRAPH, 'Producer source call graph differs')
    for name, record in source['code_blobs'].items():
        file = checked_record(record, 4 * 1024**2)
        expected = subprocess.check_output(['git', '--no-optional-locks', '-C', str(recipe), 'show', PRODUCER + ':' + name])
        oid = hashlib.sha1(b'blob ' + str(len(expected)).encode() + b'\0' + expected).hexdigest()
        need(file.read_bytes() == expected and record.get('git_blob_sha1') == oid,
             'Producer call code differs from approved Git blob: ' + name)
        need((Path(recipe) / name).read_bytes() == expected,
             'Consumer recipe differs from approved producer Git blob: ' + name)
    workflow = (Path(recipe) / '.github/workflows/firmware.yml').read_bytes()
    need(hashlib.sha256(workflow).hexdigest() == completion['workflow_source_sha256']
         and b'set -o pipefail' in workflow and b'--source "$RUNNER_TEMP/firmware-build/source"' in workflow,
         'Producer workflow lacks strict real-source verification')
    artifacts = download.get('artifacts')
    need(isinstance(artifacts, dict) and artifacts, 'Authenticated artifact receipts missing')
    for artifact in artifacts.values():
        item, archive = artifact['api'], artifact['zip']
        checked_record(archive, 2 * 1024**3)
        need(item.get('expired') is False and item.get('workflow_run', {}).get('id') == RUN
             and item['workflow_run'].get('head_sha') == PRODUCER
             and item.get('digest') == 'sha256:' + archive.get('sha256', '')
             and item.get('size_in_bytes') == archive.get('size'), 'Artifact API digest/run differs')


class HostedContext:
    checked_record = staticmethod(checked_record)

    def __init__(self, proof, records, data, recipe, raw, profile, native):
        self.proof, self.records, self.data = proof, records, data
        self.recipe, self.raw = Path(recipe), Path(raw)
        self.profile, self.native = profile, native
        self.lock = json_file(self.raw / 'lock.json')
        self.target_identity = None
        self.tools = {}
        for name, record in proof['tools'].items():
            need(name in {'fwtool', 'unsquashfs4', 'jsmin'}, 'Unknown hosted host tool')
            path = checked_record(record, 64 * 1024**2)
            need(not path.is_relative_to(self.raw) and record.get('authority') == 'independently-reviewed-host-tool'
                 and os.access(path, os.X_OK), 'Imported RAW executable is not a trusted inspection tool')
            self.tools[name] = path
        need({'fwtool', 'unsquashfs4'} <= self.tools.keys(), 'Trusted hosted inspection tools missing')
        self.scope = {'context_kind': 'hosted-latest-v1',
                      'producer_source_validation': 'producer-side-inferred-from-authenticated-successful-producer-export-and-verifier',
                      'independent_source_continuity': None, 'local_native_source_claimed': False}
        self.scope['hosted_context_sha256'] = proof['_envelope_sha256']

    def validate_smoke_scope(self, smoke):
        need(smoke.get('hosted_context') == self.scope,
             'Hosted smoke does not bind this exact hosted context and source-validation scope')

    def validate_inspector_dependencies(self, verifier):
        features = verifier.image_features
        for imported, name in ((features, 'image_features'), (features.asu_client, 'asu_client'),
                               (features.pbr_sources, 'pbr_sources'), (features.vendor_country, 'vendor_country'),
                               (verifier.apk_world, 'apk_world')):
            expected = self.recipe / 'scripts' / (name + '.py')
            need(Path(imported.__file__).resolve() == expected.resolve()
                 and expected.read_bytes() == subprocess.check_output(
                     ['git', '--no-optional-locks', '-C', str(self.recipe), 'show', PRODUCER + ':scripts/' + name + '.py']),
                 'Hosted inspector dependency differs from pinned producer recipe: ' + name)
        need(Path(features.verify.__code__.co_filename).resolve() == (self.recipe / 'scripts/image_features.py').resolve(),
             'Hosted feature verification loop was replaced')

    def verify_tree(self, tree, attestation):
        """Only after normal verify_archive(source=None, actual RAW bank) succeeds."""
        tree = Path(tree)
        persisted, witness = (self.data[k] for k in ('persisted_ib', 'kernel_witness'))
        need(sha(tree / 'ax6000-imagebuilder.json') == persisted['attestation_sha256']
             and attestation['identity'] == identity(self.profile), 'Persisted IB attestation differs')
        contexts = {r['path']: r for r in attestation['context']}
        need(len(contexts) == len(attestation['context']), 'Duplicate hosted IB context')
        kernel_configs = [name for name in contexts if name.endswith('/.config')]
        need(len(kernel_configs) == 1, 'Hosted IB kernel config is ambiguous')
        base = str(Path(kernel_configs[0]).parent)
        # Reconcile all seven SDK-prepared contexts independently, including the
        # additional records not carried in the smaller ImageBuilder inventory.
        prepared = witness['prepared_context_files']
        need(set(prepared) == CONTEXTS and set(witness['matching_contexts']) >= CONTEXTS,
             'Hosted SDK kernel witness lacks prepared context')
        need(witness['matching_contexts'] == self.native['sdk_context']['matching_contexts'],
             'Hosted SDK context is not the independently accepted native context')
        for name in CONTEXTS:
            path = checked_record(prepared[name], 64 * 1024**2)
            need({k: prepared[name][k] for k in ('size', 'sha256')} == witness['matching_contexts'][name],
                 'Hosted SDK context differs from native evidence: ' + name)
            candidate = tree / base / name
            if candidate.exists():
                need(sha(candidate) == sha(path), 'Retained IB/SDK context differs: ' + name)
        kernels = witness['functional_layouts']
        need(set(kernels) == LAYOUTS, 'Hosted functional kernel layout coverage differs')
        self.kernels = {}
        actual_kernel = checked_record(self.proof['functional_kernel'], 64 * 1024**2)
        for layout, record in kernels.items():
            expected = self.native['layouts'][layout]['kernel']
            need(record['sha256'] == expected['sha256'] and record['size'] == expected['size'],
                 'Hosted functional kernel differs from native image')
            need(record == {key: self.proof['functional_kernel'][key] for key in ('sha256', 'size')},
                 'Retained actual functional Image differs from hosted witness')
            self.kernels[layout] = actual_kernel
        image_records = [r for n, r in contexts.items() if n.endswith('/Image')]
        need(len(image_records) == 1 and all(r['sha256'] == image_records[0]['sha256']
                                           for r in kernels.values()), 'IB functional Image differs from all native layouts')
        self.kernel = self.kernels['stock']
        self.kernel_config = (tree / kernel_configs[0]).read_bytes()
        for layout in LAYOUTS:
            digest = self.native['layouts'][layout]['device_tree']['sha256']
            need(any(name.endswith('.dtb') and record['sha256'] == digest for name, record in contexts.items()),
                 'Hosted IB omits the actual native layout DTB: ' + layout)
        old_record = witness['prior_opkg_context']
        need(old_record.get('sha256') == OLD_CONTEXT, 'Hosted prior kernel evidence pin differs')
        old = json_file(checked_record(old_record))
        manifest = json_file(self.raw / 'firmware-manifest.json')
        need(old['source_commit'] == SOURCE and old['kernel_abi'] == self.profile['firmware']['kernel_version']
             and old['old_source_patches'] == manifest['source_patches'], 'Hosted prior source/kernel context differs')
        for name, actual in (('.config', self.kernel_config),
                             ('Module.symvers', checked_record(prepared['Module.symvers'], 64 * 1024**2).read_bytes()),
                             ('Image', self.kernel.read_bytes())):
            checked_record(old['files'][name], 64 * 1024**2)
            need(hashlib.sha256(actual).hexdigest() == old['files'][name]['sha256']
                 and len(actual) == old['files'][name]['size'], 'Hosted old/new functional kernel differs: ' + name)
        packageinfo = tree / 'tmp/.packageinfo'
        need('tmp/.packageinfo' in contexts and sha(packageinfo) == contexts['tmp/.packageinfo']['sha256'],
             'Hosted IB package metadata differs')
        guard = module(self.recipe / 'scripts/apk_world.py', 'hosted_apk_guard')
        hook = (tree / 'include/rootfs.mk').read_bytes()
        need(hook.decode().count(guard.HOOK) == 1
             and hashlib.sha256(hook.decode().replace(guard.HOOK, guard.ANCHOR).encode()).hexdigest() == guard.ROOTFS_SHA256,
             'Hosted APK rootfs hook differs from reviewed preimage')
        need((tree / 'scripts/ax6000-apk-world.py').read_bytes() == (self.recipe / 'scripts/apk_world.py').read_bytes(),
             'Hosted APK guard differs from approved recipe')
        roots = set(guard.core_recipe_roots(packageinfo.read_text())) | guard.ESSENTIAL | guard.VENDOR | guard.APK_PROVIDERS
        self.policy = {'schema_version': 1, 'package_manager': 'apk', 'cohort': '612-latest',
                       'protected_roots': sorted(roots)}
        policy_bytes = (json.dumps(self.policy, indent=2, sort_keys=True) + '\n').encode()
        need((tree / 'ax6000-apk-world-policy.json').read_bytes() == policy_bytes,
             'Hosted APK policy differs from independently computed native roots')
        guard_proof = guard.configure_source(self.profile, tree, check_only=True)
        need({**guard_proof, 'policy_sha256': sha(tree / 'ax6000-apk-world-policy.json')} == manifest['apk_world'],
             'Hosted APK source hook/helper/policy differs from actual native RAW manifest')
        for name in ('scripts/ax6000-ib-abi.py', 'scripts/package_format.py'):
            need((tree / name).read_bytes() == (self.recipe / 'scripts' / Path(name).name).read_bytes(),
                 'Hosted ABI helper differs from approved recipe')
        self.native_public_key = (tree / 'keys/ax6000-native.pem').read_bytes()
        need(hashlib.sha256(self.native_public_key).hexdigest() == attestation['native_apk_public_key_sha256'],
             'Hosted native APK public key differs')
        self.verify_overlay()
        self.tree_verified = True
        return self

    def verify_overlay(self):
        overlay = self.data['overlay']
        expected = self.expected_overlay()
        actual = overlay['rootfs_overlay']
        need(set(actual) == set(OVERLAY) and set(overlay['all_layouts']) == LAYOUTS,
             'Hosted rootfs overlay inventory/layouts differ')
        self.overlay = {}
        for name, mode in OVERLAY.items():
            record = actual[name]
            content = base64.b64decode(record['content_base64'], validate=True)
            need(len(content) <= 64 * 1024 and base64.b64encode(content).decode() == record['content_base64']
                 and hashlib.sha256(content).hexdigest() == record['sha256']
                 and record.get('mode') in (mode, f'{mode:04o}') and content == expected[name][0],
                 'Hosted image overlay differs from independently rendered recipe: ' + name)
            self.overlay[name] = {'content_base64': base64.b64encode(content).decode(),
                                  'sha256': record['sha256'], 'mode': mode}
            for layout in LAYOUTS:
                observed = overlay['all_layouts'][layout]
                need(observed['image_sha256'] == self.native['layouts'][layout]['image_sha256']
                     and observed['verified_overlay_paths'] == sorted(OVERLAY),
                     'Hosted overlay is not bound to all actual native images')

    def bind_catalog(self, path, digest):
        """HTTP inspector only: bind the actual post-promotion eight-field identity."""
        need(getattr(self, 'tree_verified', False), 'Verify hosted IB context before binding a catalog')
        path = Path(path).absolute()
        checked_record({'path': str(path), 'size': path.stat().st_size, 'sha256': digest}, 8 * 1024**2)
        data = json_file(path)
        need(data.get('cohort') == '612-latest' and data.get('package_manager') == 'apk'
             and data.get('build_id') == self.profile['build_id'] and data.get('source_commit') == SOURCE
             and data.get('seed') == self.profile['asu']['seed']
             and data['firmware']['kernel_version'] == self.profile['firmware']['kernel_version']
             and isinstance(data.get('snapshot_sha256'), str) and SHA.fullmatch(data['snapshot_sha256']),
             'Hosted HTTP catalog belongs to another native generation')
        self.target_identity = {'schema_version': 1, 'cohort': '612-latest', 'package_manager': 'apk',
                                'build_id': data['build_id'], 'seed': data['seed'],
                                'catalog_sha256': digest, 'snapshot_sha256': data['snapshot_sha256'],
                                'kernel_version': data['firmware']['kernel_version']}
        return self

    def expected_overlay(self):
        renderer = module(self.recipe / 'scripts/prepare-firmware.py', 'hosted_repository_renderer')
        files = renderer.apk_repository_files(self.profile)
        result = {name.removeprefix('files/'): (data, OVERLAY[name.removeprefix('files/')])
                  for name, data in files.items()}
        client = module(self.recipe / 'scripts/asu_client.py', 'hosted_asu_renderer')
        policy = client.policy(self.profile)
        native_identity = {'schema_version': 1, 'cohort': policy['cohort'], 'seed': policy['seed'], 'package_manager': 'apk'}
        result['etc/asu-cohort.json'] = ((json.dumps(native_identity, sort_keys=True) + '\n').encode(), 0o644)
        if self.target_identity is not None:
            result['etc/asu-cohort.json'] = ((json.dumps(self.target_identity, sort_keys=True, separators=(',', ':')) + '\n').encode(), 0o644)
        result['etc/uci-defaults/99-ax6000-asu'] = ((
            '#!/bin/sh\n# Bind upgrades to this image\'s kernel cohort; preserve client preferences.\n'
            'uci -q set attendedsysupgrade.server=server\n'
            f"uci -q set attendedsysupgrade.server.url='{policy['server_url']}'\n"
            'uci -q commit attendedsysupgrade\nexit 0\n').encode(), 0o755)
        need(set(result) == set(OVERLAY), 'Hosted independent overlay renderer differs')
        return result


def load(path, digest, *, cohort, profile, native, raw, recipe):
    require_latest(profile)
    need(cohort == '612-latest' and isinstance(digest, str) and SHA.fullmatch(digest),
         'Explicit latest hosted-context SHA256 required')
    path = Path(path).absolute()
    checked_record({'path': str(path), 'size': path.stat().st_size, 'sha256': digest})
    proof = json_file(path)
    need(proof.get('schema_version') == 1 and proof.get('kind') == 'ax6000-asu-hosted-context-v1'
         and proof.get('identity') == identity(profile) and proof.get('producer_commit') == PRODUCER
         and proof.get('producer_seed') == SEED,
         'Hosted context generation/producer differs')
    need(subprocess.check_output(['git', '--no-optional-locks', '-C', str(recipe), 'rev-parse', 'HEAD'], text=True).strip() == PRODUCER,
         'Hosted context requires the exact reviewed producer checkout')
    original = json.loads(subprocess.check_output(['git', '--no-optional-locks', '-C', str(recipe),
                          'show', PRODUCER + ':profiles/redmi-ax6000-612-latest-new.json']))
    for name in ('asu', 'package_only', 'image_packages', 'pbr_source', 'vendor_country_db', 'apk_key_sha256'):
        need(profile.get(name) == original.get(name), 'Hosted generated native policy differs from producer profile: ' + name)
    needed = {'completion', 'api', 'download', 'kernel_witness', 'overlay', 'persisted_ib',
              'native_acceptance', 'native_evidence', 'independent_verification'}
    need(set(proof.get('receipts', {})) == needed, 'Hosted receipt roles are incomplete')
    data = {name: json_file(checked_record(record)) for name, record in proof['receipts'].items()}
    native_sha = proof['receipts']['native_evidence']['sha256']
    need(data['native_evidence'] == native and native.get('ok') is True and native['build_id'] == profile['build_id']
         and native['source_commit'] == SOURCE and set(native['layouts']) == LAYOUTS,
         'Hosted native evidence differs')
    expected = {'profile.json', 'lock.json', 'firmware-manifest.json', 'build.config'}
    need(set(proof.get('native_inputs', {})) == expected, 'Hosted native metadata roles differ')
    for name, record in proof['native_inputs'].items():
        file = checked_record(record, 32 * 1024**2)
        need(file == Path(raw).absolute() / name, 'Hosted native input is outside actual RAW')
    need(json_file(Path(raw) / 'profile.json') == profile, 'Hosted RAW profile differs')
    manifest = json_file(Path(raw) / 'firmware-manifest.json')
    need(manifest['recipe_commit'] == PRODUCER and manifest['source_commit'] == SOURCE
         and manifest['build_id'] == profile['build_id'], 'Hosted RAW manifest generation differs')
    sdk = checked_record(proof['sdk_archive'], 2 * 1024**3)
    need(sha(sdk) == profile['sdk']['sha256'], 'Hosted original SDK archive differs')
    witness, overlay, persisted = (data[k] for k in ('kernel_witness', 'overlay', 'persisted_ib'))
    for item in (witness, overlay, persisted):
        need(item.get('ok') is True and item.get('producer_commit') == PRODUCER
             and item.get('source_commit') == SOURCE and item.get('build_id') == profile['build_id']
             and item.get('seed') == profile['asu']['seed'] and item.get('native_evidence_sha256') == native_sha,
             'Hosted receipt generation chain differs')
    need(witness['raw_manifest_sha256'] == proof['native_inputs']['firmware-manifest.json']['sha256']
         and witness['input_sdk_sha256'] == proof['sdk_archive']['sha256']
         and persisted['raw_manifest_sha256'] == witness['raw_manifest_sha256']
         and persisted['archive_sha256'] == profile['imagebuilder']['sha256'], 'Hosted SDK/IB/RAW chain differs')
    need(persisted['kind'] == 'ax6000-hosted-imagebuilder-persisted-verification-v1'
         and witness['kind'] == 'ax6000-hosted-native-kernel-witness-v1'
         and overlay['kind'] == 'ax6000-hosted-native-rootfs-overlay-v1'
         and overlay['full_native_source_claimed'] is False, 'Hosted receipt kinds/scope differ')
    need(persisted.get('native_source_proxy_created') is False and persisted.get('raw_executable_executed') is False,
         'Hosted persisted verifier must not claim a source proxy or execute RAW tools')
    checks = persisted['independently_revalidated']
    need(checks.get('full_native_source') is False and all(checks.get(name) is True for name in
         ('persisted_native_apk_bank_vs_actual_raw', 'signed_index_and_keys', 'all_persisted_context_hashes',
          'reviewed_abi_helpers', 'tracked_source_makefile_transformation', 'tracked_source_bundler_digest',
          'raw_native_apk_source_elf_digest', 'apk_world_hook_helper_policy', 'sdk_prepared_kernel_config',
          'three_functional_kernels')) and set(checks.get('three_layout_dtbs', {})) == LAYOUTS
         and all(checks['three_layout_dtbs'].values()), 'Hosted persisted independent verification is incomplete')
    checked_record(persisted['archive'], 2 * 1024**3)
    checked_record(persisted['attestation'])
    need(persisted['archive']['sha256'] == persisted['archive_sha256']
         and persisted['attestation']['sha256'] == persisted['attestation_sha256'],
         'Hosted persisted archive/attestation records differ')
    accepted, independent = data['native_acceptance'], data['independent_verification']
    need(accepted.get('ok') is True and accepted.get('all_layouts_verified') is True
         and accepted.get('hosted_kernel_witness_verified') is True
         and accepted.get('local_native_source_git_claimed') is False
         and accepted.get('facts_finalized_after_all_native_checks') is True
         and accepted.get('source_context_kind') == 'hosted-native-witness'
         and accepted.get('evidence_sha256') == native_sha
         and accepted.get('producer_commit') == PRODUCER and accepted.get('source_commit') == SOURCE
         and accepted.get('build_id') == profile['build_id'], 'Hosted independent acceptance is incomplete')
    for name in ('profile.json', 'lock.json', 'firmware-manifest.json'):
        need(accepted['native_inputs'][name] == {key: proof['native_inputs'][name][key] for key in ('size', 'sha256')},
             'Hosted accepted native metadata differs')
    need(accepted['hosted_kernel_witness'] == {key: proof['receipts']['kernel_witness'][key] for key in ('size', 'sha256')}
         and checked_record(accepted['independent_verification']) == checked_record(proof['receipts']['independent_verification']),
         'Hosted independent acceptance chain differs')
    need(independent.get('kind') == 'latest-apk-artifact-native-independent-verification'
         and independent.get('ok') is True and independent.get('run_id') == RUN
         and independent.get('recipe_commit') == PRODUCER and independent.get('source_commit') == SOURCE
         and independent.get('build_id') == profile['build_id'] and independent.get('raw_tools_executed') is False
         and independent.get('native_cloud_evidence_sha256') == native_sha
         and independent.get('download_receipt_sha256') == proof['receipts']['download']['sha256'],
         'Hosted independent artifact verification differs')
    need(independent.get('asu_seed') == accepted.get('seed') == profile['asu']['seed']
         and independent.get('kernel_abi') == accepted.get('kernel_abi') == witness.get('kernel_abi')
         == profile['firmware']['kernel_version']
         and independent.get('sdk_sha256') == proof['sdk_archive']['sha256']
         and accepted.get('channel') == 'latest' and accepted.get('package_manager') == 'apk'
         and independent.get('package_manager') == 'apk' and set(independent.get('layouts', {})) == LAYOUTS,
         'Hosted accepted kernel/seed/SDK/layout scope differs')
    for name, field in [('profile.json', 'raw_profile_sha256'), ('lock.json', 'raw_lock_sha256'),
                        ('firmware-manifest.json', 'raw_manifest_sha256')]:
        need(independent.get(field) == proof['native_inputs'][name]['sha256'],
             'Hosted independent RAW metadata link differs')
    for role, field in [('persisted_ib', 'imagebuilder_persisted_verification'), ('overlay', 'rootfs_overlay_evidence')]:
        need(independent[field]['sha256'] == proof['receipts'][role]['sha256']
             and independent[field]['path'] == proof['receipts'][role]['path'], 'Hosted artifact proof link differs')
    need(checked_record(persisted['producer_side_source_validation']['completion'])
         == checked_record(proof['receipts']['completion']), 'Producer source completion binding differs')
    need(checked_record(data['completion']['api_records']) == checked_record(proof['receipts']['api'])
         and data['completion']['download_receipt_sha256'] == proof['receipts']['download']['sha256'],
         'Hosted completion API/artifact chain differs')
    verify_producer(data['completion'], data['api'], data['download'], persisted, recipe)
    artifacts = data['download']['artifacts']
    raw_name, diagnostics_name = ('ax6000-firmware-sdk-packages-' + str(RUN),
                                  'ax6000-build-diagnostics-' + str(RUN))
    need(set(artifacts) == {raw_name, diagnostics_name}
         and all(item['api'].get('name') == name for name, item in artifacts.items()),
         'Hosted artifact names differ from the approved producer contract')
    raw_artifact, diagnostic_artifact = artifacts[raw_name], artifacts[diagnostics_name]
    need(Path(raw_artifact['extracted']) == Path(raw).absolute(), 'Hosted RAW artifact root differs')
    for name, record in proof['native_inputs'].items():
        artifact_member(raw_artifact, name, record)
    evidence_record = proof['receipts']['native_evidence']
    evidence_relative = Path(evidence_record['path']).relative_to(Path(diagnostic_artifact['extracted']))
    artifact_member(diagnostic_artifact, evidence_relative.as_posix(), evidence_record)
    proof['_envelope_sha256'] = digest
    return HostedContext(proof, proof['receipts'], data, recipe, raw, profile, native)
