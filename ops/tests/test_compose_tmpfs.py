"""Render the actual deployment tmpfs entries and inspect never-started containers."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[2]
IMAGE = 'sha256:2398ea9311ca86441bd2c5756646caf2b5831f5d2c2a63c2d86373d5c527e653'
EXPECTED = {
    'api66': '/tmp:size=32m,mode=1777',
    'worker': '/tmp:size=64m,mode=1777',
    'frontend': '/tmp:size=16m,mode=1777,uid=101,gid=101',
    'immutable_mirror': '/tmp:size=128m,mode=1777',
}


def model():
    # Parser-only sentinels never activate catalogs, mounts or service images.
    env = dict(os.environ, ASU_SERVICE_IMAGE='config.invalid/asu@sha256:' + 'a' * 64,
        ASU_REDIS_IMAGE='config.invalid/redis@sha256:' + 'b' * 64,
        ASU_STATE_DIR='/tmp/asu-tmpfs-parser-only', ASU_BUILD_UID='2000', ASU_BUILD_GID='2000',
        ASU_BUILD_LOCK_GID='987', ASU_BUILD_ENGINE_ID='config-only-not-an-engine',
        ASU_ROOTLESS_SOCKET='/run/user/2000/docker.sock', CATALOG_66_SHA256='c' * 64,
        CATALOG_612_RECOMMENDED_SHA256='d' * 64, CATALOG_612_LATEST_SHA256='e' * 64,
        ASU_MIRROR_REGISTRY_SHA256='f' * 64, ASU_MIRROR_APK_SHA256='1' * 64,
        ASU_MIRROR_APK='/tmp/asu-tmpfs-parser-only/apk')
    result = subprocess.run(['docker', 'compose', '-p', 'asu-tmpfs-parser-only',
        '-f', str(ROOT / 'deploy/compose.yml'), '-f', str(ROOT / 'deploy/frontend.yml'),
        '--profile', 'mirror', 'config', '--format', 'json'],
        env=env, capture_output=True, text=True, timeout=20, check=True)
    return json.loads(result.stdout)


@unittest.skipUnless(shutil.which('docker'), 'Docker Compose CLI required')
class ComposeTmpfsTests(unittest.TestCase):
    def test_deployment_model_preserves_each_entire_mount_option_string(self):
        services = model()['services']
        for service, expected in EXPECTED.items():
            with self.subTest(service=service):
                self.assertEqual(services[service]['tmpfs'], [expected])
        # The shared API anchor must apply to all three cohorts.
        for service in ('api612recommended', 'api612latest'):
            self.assertEqual(services[service]['tmpfs'], [EXPECTED['api66']])

    @unittest.skipUnless(os.environ.get('COMPOSE_TMPFS_TEST_DOCKER') == '1',
                         'Set COMPOSE_TMPFS_TEST_DOCKER=1 for actual Docker create/inspect')
    def test_actual_engine_tmpfs_maps_from_all_four_rendered_configurations(self):
        services = model()['services']
        subprocess.run(['docker', 'image', 'inspect', IMAGE], capture_output=True,
                       check=True, timeout=20)
        for service, expected in EXPECTED.items():
            with self.subTest(service=service):
                # Read the actual rendered source entries, not a hardcoded CLI
                # replacement that could conceal YAML splitting at commas.
                mounts = services[service]['tmpfs']
                self.assertEqual(mounts, [expected])
                name = 'ax6000-tmpfs-' + uuid.uuid4().hex
                cid = None
                try:
                    args = ['docker', 'create', '--name', name, '--pull=never',
                        '--network=none', '--read-only', '--cap-drop=ALL',
                        '--security-opt=no-new-privileges', '--user=1000:1000',
                        '--cpus=0.1', '--memory=32m', '--memory-swap=32m', '--pids-limit=32']
                    for mount in mounts:
                        args += ['--tmpfs', mount]
                    args += [IMAGE, '/bin/true']
                    cid = subprocess.check_output(args, text=True, timeout=20).strip()
                    actual = json.loads(subprocess.check_output(
                        ['docker', 'inspect', cid], text=True, timeout=20))[0]
                    target, options = expected.split(':', 1)
                    self.assertEqual(actual['HostConfig']['Tmpfs'], {target: options})
                    self.assertEqual(actual['HostConfig']['Binds'], None)
                    self.assertEqual(actual['Mounts'], [])
                    self.assertEqual(actual['State']['Status'], 'created')
                    self.assertFalse(actual['State']['Running'])
                    self.assertEqual(actual['State']['Pid'], 0)
                    print(json.dumps({'service': service, 'image_id': actual['Image'],
                        'tmpfs': actual['HostConfig']['Tmpfs'], 'state': 'created-never-started'}))
                finally:
                    # Only the exact container created in this subtest is removed.
                    if cid is not None:
                        subprocess.run(['docker', 'rm', cid], check=True,
                                       capture_output=True, timeout=20)


if __name__ == '__main__':
    unittest.main()
