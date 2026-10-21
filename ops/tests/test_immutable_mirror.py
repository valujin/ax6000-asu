"""ASGI checks against real APK3 metadata/signatures; network is mocked by default."""
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

import httpx
from fastapi.testclient import TestClient

MODULE = Path(__file__).resolve().parents[1] / 'immutable_mirror.py'
APK = Path(os.environ.get('MIRROR_TEST_APK', '/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/task-tools/apk-3.0.5/build/src/apk'))


def digest(data):
    return hashlib.sha256(data).hexdigest()


@unittest.skipUnless(APK.is_file(), 'set MIRROR_TEST_APK to a trusted host APK3 binary')
class MirrorTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location('test_mirror_module', MODULE)
        self.module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.module
        spec.loader.exec_module(self.module)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cache = self.root / 'cache'
        self.payload = self.root / 'payload'
        self.payload.mkdir()
        (self.payload / 'message').write_text('sample original payload\n')
        self.private = self.root / 'private.pem'
        self.public = self.root / 'public.pem'
        self.run_tool('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', self.private)
        self.run_tool('openssl', 'pkey', '-in', self.private, '-pubout', '-out', self.public)
        self.packages = []
        for number in range(1, 5):
            path = self.root / f'user-test-{number}-r1.apk'
            self.run_tool(APK, 'mkpkg', '--info', 'name:user-test', '--info', f'version:{number}-r1',
                          '--info', 'arch:aarch64_cortex-a53', '--files', self.payload, '--output', path)
            self.packages.append(path)
        self.index = self.root / 'packages.adb'
        self.run_tool(APK, '--no-network', 'mkndx', '--allow-untrusted', '--sign', self.private,
                      '--output', self.index, *self.packages)
        self.index_sha = digest(self.index.read_bytes())
        self.snapshot = 'a' * 64
        self.repository = {'feed': 'packages', 'index_sha256': self.index_sha,
                           'index_path': str(self.index), 'key_path': str(self.public),
                           'key_sha256': digest(self.public.read_bytes()), 'distribution': 'immortalwrt',
                           'base_url': 'https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/'}
        self.registry = {'schema_version': 1, 'snapshots': [{'snapshot_sha256': self.snapshot, 'repositories': [self.repository]}]}
        self.registry_path = self.root / 'registry.json'
        self.calls = []
        self.bodies = {p.name: p.read_bytes() for p in self.packages}
        self.status = 200

    def run_tool(self, *args):
        subprocess.run([str(x) for x in args], check=True, capture_output=True, timeout=30)

    def request(self, request):
        self.calls.append(str(request.url))
        return httpx.Response(self.status, stream=httpx.ByteStream(self.bodies.get(request.url.path.rsplit('/', 1)[-1], b'unknown')))

    def app(self, **kwargs):
        self.registry_path.write_text(json.dumps(self.registry))
        return self.module.create_app(self.registry_path, digest(self.registry_path.read_bytes()),
                                      APK, digest(APK.read_bytes()), self.cache,
                                      transport=httpx.MockTransport(self.request), **kwargs)

    def url(self, filename='packages.adb'):
        return f'/immutable/{self.snapshot}/public/{self.index_sha}/packages/{filename}'

    def test_01_serves_original_signed_index_without_network_or_resigning(self):
        with TestClient(self.app()) as client:
            result = client.get(self.url())
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.content, self.index.read_bytes())
        self.assertEqual(self.calls, [])
        self.assertIn('immutable', result.headers['cache-control'])

    def test_lazy_verified_cache_survives_upstream_unavailability(self):
        with TestClient(self.app()) as client:
            result = client.get(self.url(self.packages[0].name))
            self.assertEqual(result.status_code, 200, result.text)
            self.assertEqual(result.content, self.packages[0].read_bytes())
            self.status = 503
            repeated = client.get(self.url(self.packages[0].name))
            self.assertEqual(repeated.content, result.content)
        self.assertEqual(len(self.calls), 1)
        files = list((self.cache / 'payload').rglob('*.apk'))
        self.assertEqual(len(files), 1)
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_unknown_or_injected_paths_never_reach_origin(self):
        with TestClient(self.app()) as client:
            for path in [self.url('user-test-99.apk'), self.url('../packages.adb'), self.url('https:%2F%2Fevil.apk'),
                         self.url('user-test-1-r1.apk').replace(self.snapshot, 'b' * 64),
                         self.url().replace('/packages/', '/base/'), self.url().replace(self.index_sha, 'c' * 64)]:
                self.assertEqual(client.get(path).status_code, 404, path)
        self.assertEqual(self.calls, [])

    def test_registry_index_and_host_tool_hashes_are_required(self):
        self.registry_path.write_text(json.dumps(self.registry))
        with self.assertRaises(ValueError):
            self.module.create_app(self.registry_path, '0' * 64, APK, digest(APK.read_bytes()), self.cache)
        with self.assertRaises(ValueError):
            self.module.create_app(self.registry_path, digest(self.registry_path.read_bytes()), APK, '0' * 64, self.cache)
        self.repository['index_sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            self.app()

    def test_wrong_official_key_rejects_registry_activation(self):
        self.run_tool('openssl', 'ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', self.private)
        self.run_tool('openssl', 'pkey', '-in', self.private, '-pubout', '-out', self.public)
        self.repository['key_sha256'] = digest(self.public.read_bytes())
        with self.assertRaises(ValueError):
            self.app()

    def test_malformed_adb_and_duplicate_registry_fields_rejected(self):
        self.index.write_bytes(b'ADBdmalformed-index')
        self.repository['index_sha256'] = digest(self.index.read_bytes())
        with self.assertRaises(ValueError):
            self.app()
        self.registry_path.write_text('{"schema_version":1,"schema_version":1,"snapshots":[]}')
        with self.assertRaises(ValueError):
            self.module.create_app(self.registry_path, digest(self.registry_path.read_bytes()),
                                   APK, digest(APK.read_bytes()), self.cache)

    def test_foreign_package_architecture_rejected_even_when_signed(self):
        foreign = self.root / 'foreign-1-r1.apk'
        self.run_tool(APK, 'mkpkg', '--info', 'name:foreign', '--info', 'version:1-r1',
                      '--info', 'arch:x86_64', '--files', self.payload, '--output', foreign)
        self.run_tool(APK, 'mkndx', '--allow-untrusted', '--sign', self.private,
                      '--output', self.index, foreign)
        self.repository['index_sha256'] = digest(self.index.read_bytes())
        with self.assertRaises(ValueError):
            self.app()

    def test_cache_requires_one_process_and_no_symlink(self):
        with TestClient(self.app()):
            with self.assertRaises(ValueError):
                self.app()
        target = self.root / 'outside'
        target.mkdir()
        alternative = self.root / 'unsafe-cache'
        alternative.symlink_to(target, target_is_directory=True)
        self.cache = alternative
        with self.assertRaises(ValueError):
            self.app()

    def test_unapproved_origin_and_abi_are_rejected(self):
        for origin in ['http://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/',
                       'https://user@downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/',
                       'https://downloads.immortalwrt.org.evil.invalid/releases/25.12.0/packages/aarch64_cortex-a53/packages/',
                       'https://downloads.immortalwrt.org/releases/25.12.0/targets/mediatek/filogic/packages/',
                       'https://downloads.immortalwrt.org/releases/25.12.0/packages/x86_64/packages/']:
            self.repository['base_url'] = origin
            with self.assertRaises(ValueError, msg=origin):
                self.app()

    def test_wrong_package_identity_is_never_cached(self):
        self.bodies[self.packages[0].name] = self.packages[1].read_bytes()
        with TestClient(self.app()) as client:
            self.assertEqual(client.get(self.url(self.packages[0].name)).status_code, 502)
        self.assertEqual(list(self.cache.rglob('*.apk')), [])
        self.assertEqual(list(self.cache.rglob('.download-*')), [])

    def test_corrupt_payload_and_oversized_stream_are_rejected(self):
        for body in [b'not an APK', b'x' * 4096]:
            self.bodies[self.packages[0].name] = body
            with TestClient(self.app(max_file_bytes=2048)) as client:
                self.assertEqual(client.get(self.url(self.packages[0].name)).status_code, 502)
            self.assertEqual(list(self.cache.rglob('*.apk')), [])

    def test_redirect_is_refused_without_followup_request(self):
        def redirect(request):
            self.calls.append(str(request.url))
            return httpx.Response(302, headers={'location': 'https://evil.invalid/package.apk'})
        self.request = redirect
        with TestClient(self.app()) as client:
            self.assertEqual(client.get(self.url(self.packages[0].name)).status_code, 502)
        self.assertEqual(len(self.calls), 1)

    def test_lru_eviction_and_tamper_refetch(self):
        capacity = max(p.stat().st_size for p in self.packages) + 16
        with TestClient(self.app(cache_bytes=capacity)) as client:
            for package in self.packages[:2]:
                self.assertEqual(client.get(self.url(package.name)).status_code, 200)
            files = list((self.cache / 'payload').rglob('*.apk'))
            self.assertEqual([p.name for p in files], [self.packages[1].name])
            files[0].write_bytes(b'cache was modified')
            self.assertEqual(client.get(self.url(self.packages[1].name)).status_code, 200)
        self.assertEqual(len(self.calls), 3)
        self.assertEqual(self.index.read_bytes()[:3], b'ADB')

    def test_recovered_cache_is_reverified_before_use(self):
        with TestClient(self.app()) as client:
            self.assertEqual(client.get(self.url(self.packages[0].name)).status_code, 200)
        saved = next((self.cache / 'payload').rglob('*.apk'))
        saved.write_bytes(b'x' * saved.stat().st_size)
        with TestClient(self.app()) as client:
            response = client.get(self.url(self.packages[0].name))
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.content, self.packages[0].read_bytes())
        self.assertEqual(len(self.calls), 2)

    def test_download_concurrency_is_bounded_to_two(self):
        guard = threading.Lock()
        count = 0
        maximum = 0
        original = self.request
        def delayed(request):
            nonlocal count, maximum
            with guard:
                count += 1
                maximum = max(maximum, count)
            time.sleep(0.08)
            result = original(request)
            with guard:
                count -= 1
            return result
        self.request = delayed
        with TestClient(self.app()) as client:
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                codes = list(pool.map(lambda p: client.get(self.url(p.name)).status_code, self.packages))
        self.assertEqual(codes, [200] * 4)
        self.assertEqual(maximum, 2)


@unittest.skipUnless(os.environ.get('MIRROR_OFFICIAL_SMOKE') and APK.is_file(),
                     'set MIRROR_OFFICIAL_SMOKE to the pinned research evidence directory')
class OfficialSmoke(unittest.TestCase):
    def test_one_real_official_apk_through_asgi(self):
        spec = importlib.util.spec_from_file_location('official_mirror_module', MODULE)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        evidence = Path(os.environ['MIRROR_OFFICIAL_SMOKE'])
        index = evidence / 'immortalwrt-packages.adb'
        key = evidence / 'keys/immortalwrt-25.12.pem'
        index_sha = 'a8e0dc9b61e4eaa3077e2871f036b913137f0de6aa49be8be45438c91fe024d0'
        key_sha = 'c0da9b5747f3fb16ea64fa37acda4df3723ac22ec30ca0dc6f5c89efc0161f1f'
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            registry = {'schema_version': 1, 'snapshots': [{'snapshot_sha256': 'a'*64, 'repositories': [{
                'feed':'base', 'index_sha256':index_sha, 'index_path':str(index),
                'distribution':'immortalwrt', 'key_path':str(key), 'key_sha256':key_sha,
                'base_url':'https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/base/'}]}]}
            source = root / 'registry.json'
            source.write_text(json.dumps(registry))
            app = module.create_app(source, digest(source.read_bytes()), APK, digest(APK.read_bytes()), root/'cache')
            base = '/immutable/'+'a'*64+'/public/'+index_sha+'/base/'
            with TestClient(app) as client:
                self.assertEqual(client.get(base+'packages.adb').content, index.read_bytes())
                response = client.get(base+'6in4-29.apk')
                self.assertEqual(response.status_code, 200, response.text)
                self.assertEqual(digest(response.content), 'cfa3e687c3b29a5025272e56fa8e5c60720729a191e5462753f161600afa438e')
            self.assertEqual(len(list((root/'cache/payload').rglob('*.apk'))), 1)


if __name__ == '__main__':
    unittest.main()
