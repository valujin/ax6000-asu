"""Synthetic callback isolation tests; these never certify firmware artifacts."""
import hashlib
import importlib.util
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('hosted_inspection', Path(__file__).parents[1] / 'hosted_inspection.py')
inspection = importlib.util.module_from_spec(SPEC); SPEC.loader.exec_module(inspection)


class HostedInspectorContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.recipe = Path(self.temp.name)
        self.file = self.recipe / 'scripts/verify-firmware.py'; self.file.parent.mkdir()
        self.file.write_text('''sentinel = object()
apk_root_policy = object()
image_features = object()
def inspect_root(*args, feature_lock=None, feature_source=None, apk=None):
    assert feature_source is None
    return dict(policy=apk_root_policy, features=image_features, sentinel=sentinel)
''')
        spec = importlib.util.spec_from_file_location('synthetic_frozen_inspector', self.file)
        self.verifier = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.verifier)
        self.profile = {'package_only': ['tailscale'], 'build_id': 'SYNTHETIC'}
        self.hosted = SimpleNamespace(recipe=self.recipe, profile=self.profile, tree_verified=True,
            validate_inspector_dependencies=lambda verifier: None,
            lock={'synthetic': True}, scope={'context_kind': 'hosted-latest-v1'},
            data={'persisted_ib': {'producer_side_source_validation': {'code_blobs': {
                'scripts/verify-firmware.py': {'sha256': hashlib.sha256(self.file.read_bytes()).hexdigest()}}}}})

    def inspect(self, profile=None, manifest=None):
        return inspection.inspect_hosted_root(self.verifier, None, 'stock', None,
            self.profile if profile is None else profile, {}, {}, {}, None, b'config',
            {} if manifest is None else manifest, apk=Path('/not-executed'), hosted_context=self.hosted)

    def test_private_clone_changes_only_two_fixed_globals_and_preserves_code(self):
        original = self.verifier.inspect_root
        before = dict(original.__globals__)
        function_type = inspection.types.FunctionType
        observed = []
        def capture(code, namespace, name, defaults, closure):
            observed.append((code, namespace, defaults, closure))
            return function_type(code, namespace, name, defaults, closure)
        with patch.object(inspection.types, 'FunctionType', side_effect=capture):
            result = self.inspect()
        self.assertIs(self.verifier.inspect_root, original)
        self.assertEqual(original.__globals__, before)
        code, namespace, defaults, closure = observed[0]
        self.assertIs(code, original.__code__)
        self.assertIs(defaults, original.__defaults__)
        self.assertIs(closure, original.__closure__)
        self.assertEqual({name for name in namespace if namespace[name] is not before[name]},
                         {'apk_root_policy', 'image_features'})
        self.assertIs(result['policy'].func, inspection.apk_policy)
        self.assertIs(result['features'].verify.func, inspection.verify_features)
        self.assertIs(result['sentinel'], before['sentinel'])
        self.assertEqual(result['hosted_context']['context_kind'], 'hosted-latest-v1')

    def test_only_installed_tail_profile_exception_is_allowed(self):
        retained = {**self.profile, 'package_only': []}
        self.inspect(profile=retained, manifest={'tailscale': '1'})
        for profile, manifest in [(retained, {}), ({**retained, 'build_id': 'OTHER'}, {'tailscale': '1'}),
                                  ({**retained, 'package_only': ['other']}, {'tailscale': '1'})]:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                self.inspect(profile, manifest)

    def test_unverified_context_and_tampered_inspector_fail(self):
        self.hosted.tree_verified = False
        with self.assertRaises(ValueError): self.inspect()
        self.hosted.tree_verified = True
        self.file.write_text(self.file.read_text() + '# drift\n')
        with self.assertRaises(ValueError): self.inspect()

    def test_replaced_inspector_code_fails_even_if_module_filename_is_unchanged(self):
        self.verifier.inspect_root = lambda *args, **kwargs: {}
        with self.assertRaises(ValueError): self.inspect()

    def test_minifier_is_required_only_for_actual_enabled_build_config(self):
        payload = b'function test () { return 1; }'
        self.assertEqual(inspection.minified(payload, b'# CONFIG_LUCI_JSMIN is not set\n', None), payload)
        with self.assertRaises(ValueError): inspection.minified(payload, b'CONFIG_LUCI_JSMIN=y\n', None)
        tool = self.recipe / 'untrusted'; tool.write_bytes(b'#!/bin/sh\nexit 0\n'); tool.chmod(0o755)
        with self.assertRaises(ValueError): inspection.minified(payload, b'CONFIG_LUCI_JSMIN=y\n', tool)

    def test_feature_callback_keeps_original_verifier_loop_and_globals(self):
        namespace = {'expected': lambda *args: {'wrong': True}}
        exec(compile('def verify(profile, lock, installed, read_file, check_mode, source=None, native_translations=None):\n'
                     '    return expected(profile, lock, source)\n', str(self.file), 'exec'), namespace)
        features = SimpleNamespace(verify=namespace['verify'])
        verifier = SimpleNamespace(image_features=features)
        before = dict(namespace)
        independently_rendered = {'files': {'expected': (b'author bytes', 0o755)}}
        with patch.object(inspection, 'expected_features', return_value=independently_rendered):
            result = inspection.verify_features(self.hosted, verifier, {}, {}, {}, None, None)
        self.assertEqual(result, independently_rendered)
        self.assertEqual(namespace, before)
        with self.assertRaises(ValueError):
            inspection.verify_features(self.hosted, verifier, {}, {}, {}, None, None, source=Path('/fake-source'))

    def test_APP3_uses_its_distinct_common_package_release(self):
        script = self.recipe / 'files/asu-client/ax6000_asu.js'
        script.parent.mkdir(parents=True); script.write_bytes(b'SYNTHETIC app3 bytes')
        originals = {'overview.js': b'view', 'status.js': b'status', 'acl.json': b'acl',
                     'common.defaults': b'https://sysupgrade.kyarucloud.moe'}
        fixture = Path(__file__).parent / 'fixtures/deeea_asu_client.py'
        self.assertEqual(hashlib.sha256(fixture.read_bytes()).hexdigest(),
                         'f378ef66f9a0c6abb17d82b1b5247269f06688414855d20653a81ce399d05ede')
        spec = importlib.util.spec_from_file_location('actual_deeea_asu_client', fixture)
        actual = importlib.util.module_from_spec(spec); spec.loader.exec_module(actual)
        profile = {'package_manager': 'apk', 'asu': {'enabled': True, 'cohort': '612-latest',
            'server_url': 'https://asu.ezon.by/612/latest', 'seed': '7'*64}}
        self.assertEqual(actual.release(profile), '3')
        self.assertEqual(actual.common_release(profile), '2')
        client = SimpleNamespace(policy=actual.policy,
            _originals=lambda cohort: originals, patch_overview=lambda b: b, patch_status=lambda b: b,
            _acl=lambda b: b, release=actual.release, common_release=actual.common_release,
            APP_VERSION=actual.APP_VERSION)
        features = SimpleNamespace(asu_client=client, pbr_sources=SimpleNamespace(validate=lambda p,l: None), vendor_country=object())
        host = SimpleNamespace(recipe=self.recipe, expected_overlay=lambda: {})
        result = inspection.expected_features(host, SimpleNamespace(image_features=features), profile, {})
        self.assertEqual(result['versions']['attendedsysupgrade-common'], '10-r2')
        self.assertEqual(result['versions']['luci-app-attendedsysupgrade'], '20261021.2-r3')


if __name__ == '__main__': unittest.main()
