"""Synthetic negative contracts only; never accepted hosted firmware evidence."""
import base64
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('hosted_context', Path(__file__).parents[1] / 'hosted_context.py')
hosted = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hosted)


class HostedContracts(unittest.TestCase):
    def test_only_new_reviewed_producer_run_and_seed_are_selected(self):
        self.assertEqual(hosted.PRODUCER, 'deeea41a13b8e3ffff64fce6deec6f37d5085b12')
        self.assertEqual(hosted.RUN, 39691822857)
        self.assertEqual(hosted.SEED, '7578632e519ac983062468679ea9f7f52c8a4466ef2685dafafe56961801c4a5')
        profile = {'channel': 'latest', 'package_manager': 'apk',
                   'firmware': {'commit': hosted.SOURCE},
                   'asu': {'cohort': '612-latest', 'seed': hosted.SEED}}
        hosted.require_latest(profile)
        for seed in ('efb8b2add166002ea286fcf9d0fc410965a952fb96bad1f252dfbf59a0b7ff1c', None):
            with self.subTest(seed=seed), self.assertRaises(ValueError):
                hosted.require_latest({**profile, 'asu': {**profile['asu'], 'seed': seed}})

    def test_unreviewed_or_wrong_mode_never_falls_back_to_hosted(self):
        for profile in ({'channel': 'recommended', 'package_manager': 'apk'},
                        {'channel': 'latest', 'package_manager': 'opkg'}):
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                hosted.require_latest(profile)

    def test_missing_digest_and_linked_record_are_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            file = root / 'file'; file.write_bytes(b'fixture')
            for record in ({'path': str(file), 'size': 7, 'sha256': None},
                           {'path': str(file), 'size': 8, 'sha256': hosted.sha(file)}):
                with self.subTest(record=record), self.assertRaises(ValueError):
                    hosted.checked_record(record)
            link = root / 'link'; link.symlink_to(file)
            with self.assertRaises(ValueError):
                hosted.checked_record({'path': str(link), 'size': 7, 'sha256': hosted.sha(file)})


class ProducerContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.blobs = {}
        code = {}
        for name in hosted.CODE:
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            data = (b'set -o pipefail\n--source "$RUNNER_TEMP/firmware-build/source"\n'
                    if name.endswith('firmware.yml') else ('SYNTHETIC ' + name).encode())
            path.write_bytes(data); self.blobs[name] = data
            code[name] = {**record(path), 'git_blob_sha1': hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()}
        run = {'id': hosted.RUN, 'head_sha': hosted.PRODUCER, 'repository': {'full_name': 'valujin/ax6000-packages-6.12'},
               'head_repository': {'full_name': 'valujin/ax6000-packages-6.12'}, 'path': '.github/workflows/firmware.yml',
               'head_branch': 'main', 'event': 'workflow_dispatch', 'status': 'completed', 'conclusion': 'success', 'run_attempt': 1}
        steps = [dict(name=name, status='completed', conclusion='success') for name in sorted(hosted.STEPS)]
        self.api = {'run': run, 'jobs': {'jobs': [{'id': 3, 'status': 'completed', 'conclusion': 'success', 'steps': steps}]}}
        archive = self.root / 'SYNTHETIC.zip'; archive.write_bytes(b'NOT A FIRMWARE ARTIFACT')
        self.download = {**copy.deepcopy(self.api), 'artifacts': {'test': {'zip': record(archive), 'api': {
            'expired': False, 'workflow_run': {'id': hosted.RUN, 'head_sha': hosted.PRODUCER},
            'digest': 'sha256:' + hosted.sha(archive), 'size_in_bytes': archive.stat().st_size}}}}
        self.completion = {'kind': 'ax6000-hosted-native-completion-v1', 'ok': True, 'run_id': hosted.RUN,
            'head_sha': hosted.PRODUCER, 'run_status': 'completed', 'run_conclusion': 'success', 'run_attempt': 1,
            'local_container_exit_claimed': False, 'required_steps': {s['name']: {'job_id': 3, **s} for s in steps},
            'workflow_source_sha256': hosted.sha(self.root / '.github/workflows/firmware.yml')}
        self.persisted = {'producer_side_source_validation': {
            'classification': 'producer-side-inferred-from-pinned-code-and-authenticated-successful-steps',
            'independent_full_native_source_revalidation': False, 'required_steps': self.completion['required_steps'],
            'code_blobs': code, 'callgraph': hosted.CALLGRAPH}}

    def verify(self):
        with patch.object(hosted.subprocess, 'check_output', side_effect=lambda argv: self.blobs[argv[-1].split(':', 1)[1]]):
            hosted.verify_producer(self.completion, self.api, self.download, self.persisted, self.root)

    def test_saved_api_artifact_code_and_scope_chain(self):
        self.verify()  # Synthetic contract only: does not call the acceptance loader.
        mutations = [
            ('API producer', lambda: self.api['run'].update(head_sha='0' * 40)),
            ('API repository', lambda: self.api['run']['repository'].update(full_name='other/repo')),
            ('API failure', lambda: self.api['jobs']['jobs'][0]['steps'][0].update(conclusion='failure')),
            ('duplicate step', lambda: self.api['jobs']['jobs'][0]['steps'].append(self.api['jobs']['jobs'][0]['steps'][0])),
            ('artifact digest', lambda: self.download['artifacts']['test']['api'].update(digest='sha256:' + '0' * 64)),
            ('artifact producer', lambda: self.download['artifacts']['test']['api']['workflow_run'].update(head_sha='0' * 40)),
            ('artifact expiry', lambda: self.download['artifacts']['test']['api'].update(expired=True)),
            ('local source claim', lambda: self.persisted['producer_side_source_validation'].update(independent_full_native_source_revalidation=True)),
            ('missing exporter', lambda: self.persisted['producer_side_source_validation']['code_blobs'].pop('scripts/imagebuilder.py')),
            ('wrong callgraph', lambda: self.persisted['producer_side_source_validation'].update(callgraph=[])),
            ('wrong code', lambda: self.persisted['producer_side_source_validation']['code_blobs']['scripts/imagebuilder.py'].update(sha256='0' * 64))]
        saved = copy.deepcopy((self.api, self.download, self.completion, self.persisted))
        for label, mutate in mutations:
            with self.subTest(name=label):
                self.api, self.download, self.completion, self.persisted = copy.deepcopy(saved)
                mutate()
                with self.assertRaises((ValueError, KeyError)):
                    self.verify()


def record(path):
    return {'path': str(path), 'size': path.stat().st_size, 'sha256': hosted.sha(path)}


class ScopeAndInputContracts(unittest.TestCase):
    def test_smoke_scope_cannot_change_context_or_claim_full_source(self):
        context = object.__new__(hosted.HostedContext)
        context.scope = {'context_kind': 'hosted-latest-v1', 'hosted_context_sha256': 'a' * 64,
                         'independent_source_continuity': None, 'local_native_source_claimed': False,
                         'producer_source_validation': 'producer-side'}
        context.validate_smoke_scope({'hosted_context': copy.deepcopy(context.scope)})
        for key, value in [('hosted_context_sha256', 'b' * 64), ('independent_source_continuity', True),
                           ('local_native_source_claimed', True), ('producer_source_validation', 'independent')]:
            wrong = {**context.scope, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError):
                context.validate_smoke_scope({'hosted_context': wrong})
        with self.assertRaises(ValueError):
            context.validate_smoke_scope({})

    def test_duplicate_nonfinite_json_and_noncanonical_paths_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'input'
            for value in (b'{"ok":true,"ok":false}', b'{"ok":NaN}', b'[]'):
                path.write_bytes(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    hosted.json_file(path)
            path.write_bytes(b'file')
            valid = record(path)
            for value in ({**valid, 'size': True}, {**valid, 'path': str(path.parent / 'x') + '/../input'},
                          {**valid, 'sha256': 'A' * 64}, {**valid, 'size': -1}):
                with self.subTest(value=value), self.assertRaises(ValueError):
                    hosted.checked_record(value)

    def test_cached_modules_cannot_come_from_a_different_recipe(self):
        with tempfile.TemporaryDirectory() as tmp:
            recipe = Path(tmp); scripts = recipe / 'scripts'; scripts.mkdir()
            imported = {}
            for name in ('image_features', 'asu_client', 'pbr_sources', 'vendor_country', 'apk_world'):
                path = scripts / (name + '.py'); path.write_text('# SYNTHETIC ' + name + '\n')
                imported[name] = SimpleNamespace(__file__=str(path))
            features = imported['image_features']
            for name in ('asu_client', 'pbr_sources', 'vendor_country'): setattr(features, name, imported[name])
            namespace = {}; exec(compile('def verify(): pass', str(scripts / 'image_features.py'), 'exec'), namespace)
            features.verify = namespace['verify']
            verifier = SimpleNamespace(image_features=features, apk_world=imported['apk_world'])
            context = object.__new__(hosted.HostedContext); context.recipe = recipe
            with patch.object(hosted.subprocess, 'check_output', side_effect=lambda argv: (recipe / argv[-1].split(':', 1)[1]).read_bytes()):
                context.validate_inspector_dependencies(verifier)
                features.pbr_sources = SimpleNamespace(__file__='/different/recipe/scripts/pbr_sources.py')
                with self.assertRaises(ValueError): context.validate_inspector_dependencies(verifier)

    def test_tools_require_an_explicit_external_authority_and_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); raw = root / 'raw'; raw.mkdir()
            tool = root / 'tool'; tool.write_bytes(b'SYNTHETIC TOOL NEVER EXECUTED'); tool.chmod(0o755)
            (raw / 'lock.json').write_text('{}')
            valid = {**record(tool), 'authority': 'independently-reviewed-host-tool'}
            proof = {'tools': {'fwtool': valid, 'unsquashfs4': valid}, '_envelope_sha256': 'a' * 64}
            hosted.HostedContext(proof, {}, {}, root, raw, {}, {})
            for field, changed in [('authority', 'downloaded-RAW'), ('sha256', '0' * 64)]:
                wrong = copy.deepcopy(proof); wrong['tools']['fwtool'][field] = changed
                with self.subTest(field=field), self.assertRaises(ValueError):
                    hosted.HostedContext(wrong, {}, {}, root, raw, {}, {})
            tool.chmod(0o644)
            with self.assertRaises(ValueError):
                hosted.HostedContext(proof, {}, {}, root, raw, {}, {})


class OverlayAndCustodyContracts(unittest.TestCase):
    def setUp(self):
        self.context = object.__new__(hosted.HostedContext)
        self.expected = {name: (('SYNTHETIC independent expected bytes: ' + name).encode(), mode)
                         for name, mode in hosted.OVERLAY.items()}
        self.context.expected_overlay = lambda: self.expected
        self.context.native = {'layouts': {layout: {'image_sha256': 'a' * 64} for layout in hosted.LAYOUTS}}
        self.overlay = {'rootfs_overlay': {name: {'content_base64': base64.b64encode(data).decode(),
                         'sha256': hashlib.sha256(data).hexdigest(), 'mode': mode}
                         for name, (data, mode) in self.expected.items()},
                        'all_layouts': {layout: {'image_sha256': 'a' * 64, 'verified_overlay_paths': sorted(hosted.OVERLAY)}
                                        for layout in hosted.LAYOUTS}}
        self.context.data = {'overlay': self.overlay}

    def test_independent_overlay_bytes_modes_inventory_and_all_layouts(self):
        self.context.verify_overlay()
        saved = copy.deepcopy(self.overlay)
        name = 'etc/uci-defaults/99-ax6000-asu'
        changed = b'SYNTHETIC tampered image bytes'
        mutations = [
            ('mode', lambda: self.context.data['overlay']['rootfs_overlay'][name].update(mode=0o644)),
            ('tampered rehashed bytes', lambda: self.context.data['overlay']['rootfs_overlay'][name].update(
                content_base64=base64.b64encode(changed).decode(), sha256=hashlib.sha256(changed).hexdigest())),
            ('wrong hash', lambda: self.context.data['overlay']['rootfs_overlay'][name].update(sha256='0' * 64)),
            ('missing file', lambda: self.context.data['overlay']['rootfs_overlay'].pop(name)),
            ('missing layout', lambda: self.context.data['overlay']['all_layouts'].pop('mtkuboot')),
            ('different image', lambda: self.context.data['overlay']['all_layouts']['stock'].update(image_sha256='b' * 64)),
            ('incomplete layout overlay', lambda: self.context.data['overlay']['all_layouts']['ubootmod'].update(verified_overlay_paths=[]))]
        for label, mutate in mutations:
            with self.subTest(name=label):
                self.context.data = {'overlay': copy.deepcopy(saved)}
                mutate()
                with self.assertRaises(ValueError): self.context.verify_overlay()

    def test_metadata_must_equal_original_digest_bound_zip_member(self):
        import zipfile
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); path = root / 'build.config'; path.write_bytes(b'CONFIG_SYNTHETIC=y\n')
            archive = root / 'artifact.zip'
            with zipfile.ZipFile(archive, 'w') as stream: stream.writestr('build.config', path.read_bytes())
            artifact = {'zip': record(archive)}
            hosted.artifact_member(artifact, 'build.config', record(path))
            path.write_bytes(b'CONFIG_SYNTHETIC=n\n')
            with self.assertRaises(ValueError): hosted.artifact_member(artifact, 'build.config', record(path))
            with self.assertRaises(ValueError): hosted.artifact_member(artifact, 'missing.config', record(path))


class PreparedContextContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.tree = self.root / 'ib'; self.recipe = self.root / 'recipe'
        self.raw = self.root / 'raw'; self.raw.mkdir()
        def put(path, value):
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(value); return path
        self.context = object.__new__(hosted.HostedContext)
        ctx = self.context
        ctx.recipe, ctx.raw = self.recipe, self.raw
        ctx.profile = {'build_id': 'SYNTHETIC', 'firmware': {'commit': hosted.SOURCE,
                       'kernel_version': 'SYNTHETIC-ABI', 'architecture': 'SYNTHETIC-ARCH'}}
        self.attestation = {'identity': hosted.identity(ctx.profile), 'context': []}
        prepared, matching = {}, {}
        for name in hosted.CONTEXTS:
            path = put(self.root / 'prepared' / name, ('SYNTHETIC prepared ' + name).encode())
            prepared[name] = record(path); matching[name] = {k: prepared[name][k] for k in ('sha256', 'size')}
            item = put(self.tree / 'build/kernel' / name, path.read_bytes())
            self.attestation['context'].append({'path': item.relative_to(self.tree).as_posix(), **matching[name]})
        kernel = put(self.root / 'functional.Image', b'SYNTHETIC functional kernel; not executable firmware')
        ib_kernel = put(self.tree / 'build/Image', kernel.read_bytes())
        self.attestation['context'].append({'path': 'build/Image', **{k: record(ib_kernel)[k] for k in ('sha256', 'size')}})
        self.layouts = {}
        for layout in hosted.LAYOUTS:
            path = put(self.tree / ('build/' + layout + '.dtb'), ('SYNTHETIC DTB ' + layout).encode())
            self.attestation['context'].append({'path': path.relative_to(self.tree).as_posix(),
                                               **{k: record(path)[k] for k in ('sha256', 'size')}})
            self.layouts[layout] = {'kernel': {k: record(kernel)[k] for k in ('sha256', 'size')},
                                   'device_tree': {'sha256': hosted.sha(path)}, 'image_sha256': 'a' * 64}
        info = put(self.tree / 'tmp/.packageinfo', b'SYNTHETIC recipe metadata')
        self.attestation['context'].append({'path': 'tmp/.packageinfo', **{k: record(info)[k] for k in ('sha256', 'size')}})
        ctx.native = {'sdk_context': {'matching_contexts': matching}, 'layouts': self.layouts}
        self.guard = SimpleNamespace(HOOK='SYNTHETIC reviewed hook\n', ANCHOR='SYNTHETIC anchor\n',
            ROOTFS_SHA256=hashlib.sha256(b'SYNTHETIC anchor\n').hexdigest(), core_recipe_roots=lambda _: {'core'},
            ESSENTIAL={'essential'}, VENDOR={'vendor'}, APK_PROVIDERS={'apk'},
            configure_source=lambda *args, **kwargs: {'helper_sha256': 'SYNTHETIC'})
        put(self.tree / 'include/rootfs.mk', self.guard.HOOK.encode())
        for name in ('scripts/apk_world.py', 'scripts/ax6000-ib-abi.py', 'scripts/package_format.py'):
            value = ('SYNTHETIC reviewed ' + name).encode()
            put(self.recipe / name, value)
            put(self.tree / ('scripts/ax6000-apk-world.py' if name.endswith('apk_world.py') else name), value)
        self.policy = {'schema_version': 1, 'package_manager': 'apk', 'cohort': '612-latest',
                       'protected_roots': ['apk', 'core', 'essential', 'vendor']}
        policy = put(self.tree / 'ax6000-apk-world-policy.json',
                     (json.dumps(self.policy, indent=2, sort_keys=True) + '\n').encode())
        put(self.raw / 'firmware-manifest.json', json.dumps({'source_patches': [],
            'apk_world': {'helper_sha256': 'SYNTHETIC', 'policy_sha256': hosted.sha(policy)}}).encode())
        key = put(self.tree / 'keys/ax6000-native.pem', b'SYNTHETIC public key bytes only')
        self.attestation['native_apk_public_key_sha256'] = hosted.sha(key)
        old = {'source_commit': hosted.SOURCE, 'kernel_abi': 'SYNTHETIC-ABI', 'old_source_patches': [],
               'files': {'.config': prepared['.config'], 'Module.symvers': prepared['Module.symvers'], 'Image': record(kernel)}}
        self.old = put(self.root / 'old.json', json.dumps(old).encode())
        attestation_file = put(self.tree / 'ax6000-imagebuilder.json', json.dumps(self.attestation).encode())
        ctx.proof = {'functional_kernel': record(kernel)}
        ctx.data = {'persisted_ib': {'attestation_sha256': hosted.sha(attestation_file)},
                    'kernel_witness': {'prepared_context_files': prepared, 'matching_contexts': copy.deepcopy(matching),
                        'functional_layouts': {layout: item['kernel'] for layout, item in self.layouts.items()},
                        'prior_opkg_context': record(self.old)}}
        # Overlay has its own independent bytes/mode/all-layout tests above.
        ctx.verify_overlay = lambda: None

    def verify(self):
        with patch.object(hosted, 'OLD_CONTEXT', hosted.sha(self.old)), patch.object(hosted, 'module', return_value=self.guard):
            return self.context.verify_tree(self.tree, self.attestation)

    def test_seven_contexts_functional_kernels_dtbs_policy_and_helpers(self):
        self.verify()
        self.assertTrue(self.context.tree_verified)
        self.assertEqual(self.context.policy, self.policy)
        self.assertEqual(self.context.kernel_config, (self.tree / 'build/kernel/.config').read_bytes())
        mutations = [
            ('missing prepared context', lambda: self.context.data['kernel_witness']['prepared_context_files'].pop('.config.set')),
            ('wrong SDK context', lambda: self.context.data['kernel_witness']['matching_contexts']['.config'].update(sha256='0' * 64)),
            ('wrong functional kernel', lambda: self.context.proof['functional_kernel'].update(sha256='0' * 64)),
            ('missing kernel layout', lambda: self.context.data['kernel_witness']['functional_layouts'].pop('stock')),
            ('wrong DTB', lambda: self.context.native['layouts']['stock']['device_tree'].update(sha256='0' * 64)),
            ('wrong old witness', lambda: self.context.data['kernel_witness']['prior_opkg_context'].update(sha256='0' * 64)),
            ('wrong helper', lambda: (self.tree / 'scripts/ax6000-ib-abi.py').write_bytes(b'tampered')),
            ('wrong hook', lambda: (self.tree / 'include/rootfs.mk').write_bytes(b'tampered')),
            ('wrong policy', lambda: (self.tree / 'ax6000-apk-world-policy.json').write_bytes(b'{}')),
            ('wrong native key', lambda: (self.tree / 'keys/ax6000-native.pem').write_bytes(b'tampered'))]
        for label, mutate in mutations:
            with self.subTest(label=label):
                self.setUp()
                mutate()
                with self.assertRaises((ValueError, KeyError)): self.verify()


if __name__ == '__main__':
    unittest.main()
