"""Origin boundary checks; optional real pinned NGINX runs without any network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'nginx@sha256:970364228b1e4f932abc22d321932816782cca8a20b85a77552a7cfe9acfb3b5'
DOCKER_TESTS = os.environ.get('FRONTEND_TEST_DOCKER') == '1'


class FrontendContractTests(unittest.TestCase):
    def test_runtime_has_only_required_operator_modules_and_no_host_installs(self):
        recipe = (ROOT / 'Containerfile').read_text()
        runtime = recipe.rsplit('\nFROM ', 1)[1]
        self.assertIn('COPY ops/immutable_mirror.py ops/promote.py ops/builder_image.py /app/ops/', runtime)
        self.assertIn('PYTHONPATH=/app', runtime)
        self.assertNotIn('RUN ', runtime)
        self.assertNotIn('COPY ops /', runtime)

    @unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI required for merged-model check')
    def test_merged_compose_keeps_private_api_and_only_gateway_on_existing_npm_network(self):
        # These identities exist only in the config parser; never run compose up.
        environment = dict(os.environ, ASU_SERVICE_IMAGE='example.invalid/asu@sha256:' + 'a' * 64,
            ASU_REDIS_IMAGE='example.invalid/redis@sha256:' + 'b' * 64,
            ASU_STATE_DIR='/tmp/frontend-config-fixture', ASU_BUILD_UID='1000', ASU_BUILD_GID='1000',
            ASU_BUILD_LOCK_GID='1000', ASU_BUILD_ENGINE_ID='config-only-fixture',
            ASU_ROOTLESS_SOCKET='/tmp/frontend-config-fixture/docker.sock',
            CATALOG_66_SHA256='c' * 64, CATALOG_612_RECOMMENDED_SHA256='d' * 64,
            CATALOG_612_LATEST_SHA256='e' * 64, ASU_MIRROR_REGISTRY_SHA256='f' * 64,
            ASU_MIRROR_APK_SHA256='1' * 64, ASU_MIRROR_APK='/tmp/frontend-config-fixture/apk')
        result = subprocess.run(['docker', 'compose', '-p', 'asu-front-config-only',
            '-f', str(ROOT / 'deploy/compose.yml'), '-f', str(ROOT / 'deploy/frontend.yml'),
            '--profile', 'mirror', 'config', '--format', 'json'],
            env=environment, text=True, capture_output=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        model = json.loads(result.stdout)
        self.assertTrue(model['networks']['api']['internal'])
        self.assertTrue(model['networks']['npm']['external'])
        self.assertEqual(model['networks']['npm']['name'], 'nginx-proxy-manager_default')
        self.assertEqual(set(model['services']['frontend']['networks']), {'api', 'npm'})
        self.assertEqual(set(model['services']['immutable_mirror']['networks']), {'api', 'mirror_egress'})
        self.assertEqual(int(model['services']['frontend']['mem_limit']), 64 * 1024**2)
        self.assertEqual(float(model['services']['frontend']['cpus']), 0.1)
        self.assertNotIn('ports', model['services']['frontend'])
        for service in ('api66', 'api612recommended', 'api612latest', 'redis', 'immutable_mirror'):
            self.assertNotIn('npm', model['services'][service]['networks'])

    def test_gateway_has_no_socket_host_port_or_eager_upstream_dependency(self):
        compose = (ROOT / 'deploy/frontend.yml').read_text()
        frontend = compose.split('  frontend:\n', 1)[1].split('\n  immutable_mirror:', 1)[0]
        self.assertIn(IMAGE, frontend)
        self.assertIn('aliases: [ax6000-asu-front]', frontend)
        self.assertIn('name: nginx-proxy-manager_default', compose)
        for forbidden in ('ports:', 'depends_on:', 'docker.sock', 'privileged:', 'network_mode: host'):
            self.assertNotIn(forbidden, frontend)
        self.assertIn('user: "101:101"', frontend)
        self.assertIn('mem_limit: 64m', frontend)
        self.assertIn('cpus: 0.1', frontend)
        self.assertIn('read_only: true', frontend)
        mirror = compose.split('\n  immutable_mirror:', 1)[1]
        self.assertIn('profiles: [mirror]', mirror)
        self.assertIn('networks: [api, mirror_egress]', mirror)
        self.assertNotIn('docker.sock', mirror)


@unittest.skipUnless(DOCKER_TESTS, 'Set FRONTEND_TEST_DOCKER=1 for isolated actual NGINX checks')
class ActualNginxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which('docker'):
            raise RuntimeError('Docker is required for explicitly selected NGINX tests')
        cls.tmp = tempfile.TemporaryDirectory(prefix='asu-front-test-')
        cls.tree = Path(cls.tmp.name)
        cls.snapshot = 'a' * 64
        channel = cls.tree / cls.snapshot / 'channel'
        channel.mkdir(parents=True)
        (channel / 'profile.json').write_text('{"fixture":true}\n')
        (channel / 'escape.json').symlink_to('/etc/passwd')
        for path in (cls.tree, cls.tree / cls.snapshot, channel):
            path.chmod(0o755)
        # Preserve the actual router/config; only the 6.6 backend address is
        # replaced by an in-process loopback echo server. No service is deployed.
        config = (ROOT / 'deploy/frontend.conf').read_text()
        test_config = config.replace('api66:8000', '127.0.0.1:18066')
        backend = r'''
    server {
        listen 127.0.0.1:18066;
        default_type application/json;
        location = /api/v1/redirect-relative {
            absolute_redirect off;
            return 302 /json/v1/overview.json;
        }
        location = /api/v1/redirect-absolute {
            return 302 http://asu.ezon.by/json/v1/overview.json;
        }
        location / {
            return 200 '{"uri":"$request_uri","prefix":"$http_x_forwarded_prefix"}';
        }
    }
'''
        test_config = test_config.rstrip()[:-1] + backend + '}\n'
        cls.config = cls.tree / 'test-nginx.conf'
        cls.config.write_text(test_config)
        cls.config.chmod(0o644)
        cls.name = 'ax6000-front-test-' + uuid.uuid4().hex[:12]
        cls.common = ['docker', 'run', '--name', cls.name, '--network', 'none', '--user', '101:101',
            '--read-only', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '64',
            '--memory', '64m', '--memory-swap', '64m', '--cpus', '0.1',
            '--tmpfs', '/tmp:rw,size=16m,mode=1777,uid=101,gid=101',
            '--mount', f'type=bind,src={ROOT}/deploy/frontend.conf,dst=/etc/nginx/nginx.conf,readonly',
            '--mount', f'type=bind,src={cls.tree},dst=/immutable,readonly', '--entrypoint', 'nginx']
        try:
            syntax = subprocess.run(cls.common + ['--rm', IMAGE, '-t'], text=True, capture_output=True, timeout=20)
            if syntax.returncode:
                raise RuntimeError(syntax.stdout + syntax.stderr)
            mount = f'type=bind,src={ROOT}/deploy/frontend.conf,dst=/etc/nginx/nginx.conf,readonly'
            cls.common[cls.common.index(mount)] = f'type=bind,src={cls.config},dst=/etc/nginx/nginx.conf,readonly'
            started = subprocess.run(cls.common + ['--detach', IMAGE, '-g', 'daemon off;'],
                                     text=True, capture_output=True, timeout=20)
            if started.returncode:
                raise RuntimeError(started.stdout + started.stderr)
            for _ in range(20):
                probe = subprocess.run(['docker', 'exec', cls.name, 'curl', '-fsS', '--max-time', '1',
                                        'http://127.0.0.1:8080/healthz'], text=True, capture_output=True, timeout=3)
                if probe.returncode == 0:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError('Isolated gateway did not become ready')
        except BaseException:
            subprocess.run(['docker', 'rm', '-f', cls.name], capture_output=True, timeout=10)
            cls.tmp.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['docker', 'rm', '-f', cls.name], check=True, capture_output=True, timeout=10)
        cls.tmp.cleanup()

    def request(self, path, *options):
        result = subprocess.run(['docker', 'exec', self.name, 'curl', '--path-as-is', '--silent', '--show-error',
            '--max-time', '6', '--dump-header', '-', *options, 'http://127.0.0.1:8080' + path],
            capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        head, body = result.stdout.split(b'\r\n\r\n', 1)
        lines = head.decode().split('\r\n')
        headers = {}
        for line in lines[1:]:
            name, value = line.split(':', 1)
            headers[name.lower()] = value.strip()
        time.sleep(0.22)  # Respect the actual configured metadata admission rate.
        return int(lines[0].split()[1]), headers, body

    def test_root_health_cors_and_method_bounds(self):
        status, headers, body = self.request('/')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)['service'], 'ax6000-asu')
        self.assertEqual(headers['content-type'], 'application/json')
        status, headers, body = self.request('/healthz', '-X', 'OPTIONS', '-H', 'Origin: http://192.168.10.1')
        self.assertEqual(status, 204)
        self.assertEqual(headers['access-control-allow-origin'], '*')
        self.assertNotIn('access-control-allow-credentials', headers)
        self.assertEqual(self.request('/', '-X', 'DELETE')[0], 405)
        self.assertEqual(self.request('/healthz?probe=%2e')[0], 200)

    def test_static_bytes_canonical_path_readonly_and_error_cache_policy(self):
        path = '/immutable/' + self.snapshot + '/channel/profile.json'
        status, headers, body = self.request(path)
        self.assertEqual(status, 200)
        self.assertEqual(body, b'{"fixture":true}\n')
        self.assertEqual(headers['cache-control'], 'public, max-age=31536000, immutable')
        self.assertEqual(headers['access-control-allow-origin'], '*')
        self.assertEqual(self.request(path, '-X', 'POST')[0], 405)
        for suffix in ('../profile.json', '%2e%2e/profile.json', 'foo%2fprofile.json', 'foo%252eprofile.json'):
            with self.subTest(suffix=suffix):
                self.assertEqual(self.request('/immutable/' + self.snapshot + '/channel/' + suffix)[0], 400)
        for suffix in ('escape.json', '.hidden', ''):
            with self.subTest(suffix=suffix):
                status, headers, _ = self.request('/immutable/' + self.snapshot + '/channel/' + suffix)
                self.assertIn(status, (403, 404))
                self.assertEqual(headers['cache-control'], 'no-store')

    def test_real_proxy_strips_only_cohort_and_preserves_query_store_and_redirect_prefix(self):
        for suffix in ('/api/v1/revision?target=mediatek%2Ffilogic', '/store/' + 'b' * 64 + '/firmware.bin'):
            with self.subTest(suffix=suffix):
                status, headers, body = self.request('/66' + suffix)
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(body), {'uri': suffix, 'prefix': '/66'})
                self.assertEqual(headers['access-control-allow-origin'], '*')
        for suffix in ('relative', 'absolute'):
            status, headers, _ = self.request('/66/api/v1/redirect-' + suffix)
            self.assertEqual(status, 302)
            self.assertEqual(headers['location'], '/66/json/v1/overview.json')

    def test_unready_upstreams_do_not_prevent_gateway_start_and_large_requests_are_rejected(self):
        # 6.12 APIs and mirror do not exist; this container has no network/socket.
        for path in ('/612/recommended/api/v1/overview', '/612/latest/api/v1/overview'):
            status, headers, _ = self.request(path)
            self.assertEqual(status, 502)
            self.assertEqual(headers['cache-control'], 'no-store')
        self.assertEqual(self.request('/healthz')[0], 200)
        self.assertEqual(self.request('/66/api/v1/build', '-X', 'POST', '-H', 'Content-Length: 262145', '--data', '')[0], 413)


if __name__ == '__main__':
    unittest.main()
