"""Synthetic contract/command fixtures; never real firmware smoke evidence."""
from contextlib import nullcontext
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('smoke_imagebuilder', Path(__file__).parents[1] / 'smoke_imagebuilder.py')
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)


class SmokeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.profile = {'build_id': 'synthetic-build', 'firmware': {'commit': 'a' * 40,
                        'kernel_version': '6.6.1~' + 'b' * 32 + '-r1', 'architecture': 'aarch64_cortex-a53'}}
        self.controls = {name: {'Version': version} for name, version in {'kernel': self.profile['firmware']['kernel_version'],
                         'opkg': '1', 'busybox': '1', 'kmod-mt_wifi': '1', 'libubox2026': '1'}.items()}
        self.defaults = {name: item['Version'] for name, item in self.controls.items()}

    def test_make_argv_preserves_actual_names_and_omits_strip_abi(self):
        command = smoke.make_command('manifest', 'stock', self.defaults)
        self.assertEqual(command[:8], ['nice', '-n', '19', 'ionice', '-c', '3', 'make', '-s'])
        self.assertIn('PROFILE=xiaomi_redmi-router-ax6000-stock', command)
        self.assertTrue(any('libubox2026' in part and part.startswith('PACKAGES=') for part in command))
        self.assertFalse(any('STRIP_ABI' in part for part in command))
        self.assertIn('FILES=/builder/smoke-files', smoke.make_command('image', 'stock', self.defaults))
        with self.assertRaises(ValueError):
            smoke.make_command('image', 'stock', ['busybox;touch /tmp/unsafe'])

    def test_manifest_rejects_foreign_versions_dropped_defaults_and_tailscale(self):
        smoke.validate_manifest(self.defaults, self.defaults, self.controls, self.profile['firmware']['kernel_version'], 'opkg')
        for actual in [self.defaults | {'foreign': '1'}, self.defaults | {'busybox': '2'},
                       {name: version for name, version in self.defaults.items() if name != 'kmod-mt_wifi'},
                       self.defaults | {'tailscale': '1'}]:
            with self.assertRaises(ValueError):
                smoke.validate_manifest(actual, self.defaults, self.controls, self.profile['firmware']['kernel_version'], 'opkg')

    def caps(self):
        return ('cpu.max=400000 100000\ncpuset.cpus.effective=0-3\nmemory.max=10737418240\n'
                'memory.swap.max=0\npids.max=2048\nUid:\t1000\t1000\t1000\t1000\n'
                'Gid:\t1000\t1000\t1000\t1000\nNoNewPrivs:\t1\nCapEff:\t0000000000000000\n')

    def test_actual_kernel_caps_and_privileges_required(self):
        smoke.validate_caps(self.caps())
        for before, after in [('400000', 'max'), ('0-3', '0-7'), ('10737418240', 'max'),
                              ('memory.swap.max=0', 'memory.swap.max=max'), ('2048', 'max'),
                              ('NoNewPrivs:\t1', 'NoNewPrivs:\t0'), ('0000000000000000', '0000000000000001'),
                              ('Uid:\t1000', 'Uid:\t0')]:
            with self.assertRaises(ValueError):
                smoke.validate_caps(self.caps().replace(before, after))

    def test_container_pid1_owns_global_inode_independently(self):
        command = smoke.container_command('sha256:' + 'c' * 64, 'd' * 32)
        self.assertIn('--user=1000:1000', command)
        self.assertIn('--cpu-quota=400000', command)
        self.assertIn('--cpuset-cpus=0-3', command)
        self.assertIn('--memory=10g', command)
        self.assertIn('--memory-swap=10g', command)
        self.assertIn('--pids-limit=2048', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('--network=none', command)
        self.assertIn('--entrypoint=timeout', command)
        self.assertIn('flock', command)
        self.assertIn('/build-lock/.build.lock', command)
        self.assertTrue(any(smoke.LOCK in value and value.endswith(',readonly') for value in command))
        self.assertIn('1200', command)
        self.assertTrue(any('exec sleep 86400' in value for value in command))

    def test_every_cli_call_guards_dedicated_engine_and_excludes_production_socket_mount(self):
        command = smoke.client_command(['info'])
        self.assertEqual(command[:3], ['/usr/bin/docker', '--host', smoke.builder.ROOTFUL_SOCKET])
        mounts = [part for part in command if part.startswith('--mount=')]
        self.assertEqual(len(mounts), 2)
        self.assertFalse(any('/var/run/docker.sock' in part for part in mounts))
        self.assertTrue(any(smoke.builder.ROOTLESS_SOCKET in part for part in mounts))
        self.assertIn(smoke.builder.ROOTLESS_ENGINE, command)
        self.assertIn(smoke.builder.CLIENT_GUARD, command)
        self.assertIn('--user=2000:2000', command)
        self.assertIn('--memory=2g', command)
        self.assertIn('--memory-swap=2g', command)

    def test_nonce_and_actual_inode_are_required_before_make(self):
        state = json.dumps([{'State': {'Running': True}}]).encode()
        fake_stat = SimpleNamespace(st_dev=12, st_ino=34)
        with patch.object(smoke, 'client', side_effect=[state, b'a' * 32, b'12:34\n']):
            smoke.wait_lock('c' * 64, 'a' * 32, fake_stat, object())
        with patch.object(smoke, 'client', side_effect=[state, b'a' * 32, b'12:35\n']):
            with self.assertRaises(ValueError):
                smoke.wait_lock('c' * 64, 'a' * 32, fake_stat, object())
        with patch.object(smoke, 'client', side_effect=[state, b'old-token']):
            with self.assertRaises(ValueError):
                smoke.wait_lock('c' * 64, 'a' * 32, fake_stat, object())

    def test_reviewed_hardkill_proof_must_match_current_inode(self):
        stat = SimpleNamespace(st_dev=12, st_ino=34)
        proof = {'schema_version': 1, 'kind': 'ax6000-rootless-lock-hardkill', 'ok': True,
                 'engine_id': smoke.builder.ROOTLESS_ENGINE, 'lock_device': 12, 'lock_inode': 34,
                 'held_after_worker_death': True, 'released_after_container_death': True}
        smoke.validate_hardkill_proof(proof, stat)
        for key, wrong in [('held_after_worker_death', False), ('released_after_container_death', False),
                           ('engine_id', 'production'), ('lock_inode', 35)]:
            with self.assertRaises(ValueError):
                smoke.validate_hardkill_proof(proof | {key: wrong}, stat)

    def test_extracted_modules_overlay_and_features_match_independent_native_hashes(self):
        evidence = {'sha256': 'a' * 64, 'size': 123, 'mode': '0644'}
        native = {'modules': {'lib/modules/vendor.ko': evidence}, 'firmware': {'lib/firmware/radio.bin': evidence},
                  'repository_files': {'etc/opkg/distfeeds.conf': evidence},
                  'optional_features': {'files': {'www/asu.js': evidence}}}
        smoke.compare_native_root(native, native)
        for group in ('modules', 'firmware', 'repository_files'):
            with self.assertRaises(ValueError):
                smoke.compare_native_root(native | {group: {}}, native)
        with self.assertRaises(ValueError):
            smoke.compare_native_root(native | {'optional_features': {'files': {}}}, native)

    def test_overlay_tar_exact_bytes_modes_no_unreviewed_files(self):
        data = b'reviewed native cohort bytes\n'
        overlay = {'etc/asu-cohort.json': {'content_base64': base64.b64encode(data).decode(),
                    'sha256': hashlib.sha256(data).hexdigest(), 'mode': 0o644}}
        target = self.root / 'overlay.tar'
        smoke.overlay_tar(overlay, target)
        with tarfile.open(target) as archive:
            self.assertEqual(archive.getnames(), ['etc/asu-cohort.json'])
            member = archive.getmembers()[0]
            self.assertEqual(member.mode, 0o644)
            self.assertEqual(archive.extractfile(member).read(), data)
        overlay['etc/asu-cohort.json']['sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            smoke.overlay_tar(overlay, self.root / 'bad-overlay.tar')

    def export(self, members):
        target = self.root / ('output-' + str(len(list(self.root.glob('output-*')))) + '.tar')
        with tarfile.open(target, 'w') as archive:
            for member, data in members:
                archive.addfile(member, io.BytesIO(data) if data else None)
        return target

    def test_actual_output_export_forbids_links_and_escape(self):
        valid = tarfile.TarInfo('./profiles.json')
        valid.size = 2
        archive = self.export([(valid, b'{}')])
        smoke.unpack_outputs(archive, self.root / 'valid')
        self.assertEqual((self.root / 'valid/profiles.json').read_bytes(), b'{}')
        for name, kind in [('../../escape', tarfile.DIRTYPE), ('/absolute', tarfile.DIRTYPE),
                           ('secret', tarfile.SYMTYPE), ('device', tarfile.CHRTYPE)]:
            member = tarfile.TarInfo(name)
            member.type = kind
            member.linkname = '/etc/passwd'
            with self.assertRaises(ValueError):
                smoke.unpack_outputs(self.export([(member, b'')]), self.root / 'rejected')

    def args(self):
        arguments = []
        for key in ('cohort', 'image-id', 'archive-sha256', 'builder-approval-sha256', 'builder-load-receipt-sha256',
                    'native-evidence-sha256', 'snapshot-sha256', 'usign-sha256', 'recipe-commit'):
            arguments += ['--' + key, '66' if key == 'cohort' else 'a' * 64]
        for key in ('archive', 'profile', 'builder-approval', 'builder-load-receipt', 'native-evidence',
                    'snapshot-manifest', 'snapshot-signature', 'public-key', 'usign', 'source', 'raw', 'package-repository'):
            arguments += ['--' + key, str(self.root / key)]
        return arguments + ['--output', str(self.root / 'fresh')]

    def context(self):
        return {'profile': self.profile, 'approval': {'attestation_sha256': 'a' * 64},
                'defaults': {'stock': self.defaults}, 'overlay': {'etc/asu-cohort.json': {}}}

    def test_default_dry_plan_never_contacts_docker_or_writes_receipt(self):
        context = self.context()
        with patch.object(smoke, 'load_context', return_value=context), patch.object(smoke, 'prepare_native'), \
             patch.object(smoke.subprocess, 'check_output', return_value=b''), \
             patch.object(smoke.promotion, 'recipe_modules', return_value=nullcontext(self.root)), \
             patch.object(smoke, 'client') as client, patch('sys.stdout', new_callable=io.StringIO) as stdout:
            smoke.main(self.args())
            result = json.loads(stdout.getvalue())
        self.assertFalse(result['make_commands_executed'])
        self.assertEqual(set(result['layouts']), {'stock'})
        self.assertFalse((self.root / 'fresh').exists())
        client.assert_not_called()

    def test_run_refuses_missing_hardkill_proof_before_engine_access(self):
        with patch.object(smoke, 'load_context', return_value=self.context()), patch.object(smoke, 'prepare_native'), \
             patch.object(smoke.subprocess, 'check_output', return_value=b''), \
             patch.object(smoke.promotion, 'recipe_modules', return_value=nullcontext(self.root)), \
             patch.object(smoke, 'client') as client:
            with self.assertRaises(ValueError):
                smoke.main(self.args() + ['--run'])
        client.assert_not_called()
        self.assertFalse((self.root / 'fresh').exists())

    def test_receipt_identity_matches_promoter_opkg_and_apk_contract(self):
        self.assertNotIn('package_manager', smoke.identity(self.profile))
        self.assertEqual(smoke.identity(self.profile | {'package_manager': 'apk'})['package_manager'], 'apk')

    def test_synthetic_receipt_matches_promoter_artifact_contract(self):
        directory = self.root / 'stock'
        directory.mkdir()
        device = 'xiaomi_redmi-router-ax6000-stock'
        files = {'info.txt': device.encode(),
                 'image.manifest': ''.join(name + ' - ' + version + '\n' for name, version in self.defaults.items()).encode(),
                 'sysupgrade.bin': b'SYNTHETIC UNIT FIXTURE; NOT FIRMWARE',
                 'fwtool.json': json.dumps({'supported_devices': ['xiaomi,redmi-router-ax6000-stock'],
                                            'version': {'board': device, 'target': 'mediatek/filogic'}}).encode()}
        for name, contents in files.items():
            (directory / name).write_bytes(contents)
        layout = {'exit_codes': {'info': 0, 'manifest': 0, 'image': 0}, 'kernel_sha256': 'e' * 64}
        for key, name in [('info', 'info.txt'), ('manifest', 'image.manifest'), ('image', 'sysupgrade.bin'), ('metadata', 'fwtool.json')]:
            layout[key] = smoke.record(directory / name, self.root)
        profile = self.profile | {'imagebuilder': {'sha256': 'a' * 64}}
        receipt = {'schema_version': 1, 'kind': 'ax6000-imagebuilder-smoke', 'identity': smoke.identity(profile),
                   'archive_sha256': 'a' * 64, 'attestation_sha256': 'b' * 64, 'snapshot_sha256': 'c' * 64,
                   'layouts': {'stock': layout}}
        bank = {name: {'name': name, 'version': version} for name, version in self.defaults.items()}
        native = {'stock': {'kernel': {'sha256': 'e' * 64}}}
        smoke.promotion.smoke_evidence(receipt, self.root, profile, 'b' * 64, 'c' * 64, native, {'stock': self.defaults}, bank)
        (directory / 'image.manifest').write_text('tampered\n')
        with self.assertRaises(ValueError):
            smoke.promotion.smoke_evidence(receipt, self.root, profile, 'b' * 64, 'c' * 64, native, {'stock': self.defaults}, bank)


if __name__ == '__main__':
    unittest.main()
