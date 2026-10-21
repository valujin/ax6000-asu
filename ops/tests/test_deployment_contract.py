"""Compose parsing only: no daemon calls, container starts or live state writes."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI required for model inspection')
class RootlessSocketDeploymentTests(unittest.TestCase):
    def test_only_worker_receives_readonly_dedicated_socket(self):
        # Parser-only identities below never constitute activated catalog approvals.
        env = dict(os.environ, ASU_SERVICE_IMAGE='config.invalid/asu@sha256:' + 'a' * 64,
            ASU_REDIS_IMAGE='config.invalid/redis@sha256:' + 'b' * 64,
            ASU_STATE_DIR='/tmp/asu-compose-parser-only', ASU_BUILD_UID='2000', ASU_BUILD_GID='2000',
            ASU_BUILD_LOCK_GID='987', ASU_BUILD_ENGINE_ID='config-only-not-an-engine',
            ASU_ROOTLESS_SOCKET='/run/user/2000/docker.sock', CATALOG_66_SHA256='c' * 64,
            CATALOG_612_RECOMMENDED_SHA256='d' * 64, CATALOG_612_LATEST_SHA256='e' * 64)
        result = subprocess.run(['docker', 'compose', '-p', 'asu-socket-parser-only',
            '-f', str(ROOT / 'deploy/compose.yml'), 'config', '--format', 'json'],
            env=env, capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        model = json.loads(result.stdout)
        worker = model['services']['worker']
        sockets = [volume for service in model['services'].values() for volume in service.get('volumes', [])
                   if str(volume.get('target', '')).endswith('.sock')]
        self.assertEqual(len(sockets), 1)
        self.assertEqual(sockets[0]['source'], '/run/user/2000/docker.sock')
        self.assertEqual(sockets[0]['target'], '/run/ax6000-build/docker.sock')
        self.assertIs(sockets[0]['read_only'], True)
        self.assertIn(sockets[0], worker['volumes'])
        self.assertEqual(worker['environment']['ASU_BUILD_ENGINE_URL'], 'unix:///run/ax6000-build/docker.sock')
        self.assertEqual(worker['user'], '2000:2000')
        self.assertEqual(list(map(str, worker['group_add'])), ['987'])
        self.assertTrue(model['networks']['api']['internal'])
        self.assertEqual(model['networks']['egress']['driver'], 'bridge')
        self.assertFalse(model['networks']['egress'].get('internal', False))
        for name in ('api66', 'api612recommended', 'api612latest', 'worker'):
            self.assertEqual(set(model['services'][name]['networks']), {'api', 'egress'})
        self.assertEqual(set(model['services']['redis']['networks']), {'api'})
        self.assertEqual(model['services']['api66']['ports'][0]['host_ip'], '127.0.0.1')
        for service in model['services'].values():
            for volume in service.get('volumes', []):
                self.assertNotEqual(volume.get('source'), '/var/run/docker.sock')


if __name__ == '__main__':
    unittest.main()
