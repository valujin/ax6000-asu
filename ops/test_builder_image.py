import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('builder_image', Path(__file__).with_name('builder_image.py'))
image = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(image)


def digest(data):
    return hashlib.sha256(data).hexdigest()


class BuilderImageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.key = self.root / 'repository.pub'
        self.key.write_bytes(b'untrusted comment: fixture public key\n' + base64.b64encode(b'Ed' + b'k' * 40) + b'\n')
        self.proof = {
            'schema_version': 1, 'kind': 'ax6000-imagebuilder-approval', 'approved': True,
            'source_context_verified': True, 'native_bank_verified': True,
            'signatures_verified': True, 'private_keys_absent': True,
            'cohort': '66', 'package_manager': 'opkg', 'build_id': 'fixture-generation',
            'source_commit': 'a' * 40, 'kernel_version': '6.6.1~' + 'b' * 32 + '-r1',
            'profiles': ['xiaomi_redmi-router-ax6000-stock'],
            'public_key_sha256': image.sha256(self.key), 'verification_result_sha256': 'c' * 64,
        }
        self.files = {'Makefile': b'# fixture only, not executable evidence\n', '.config': b'CONFIG_IB=y\n',
                      'repositories.conf': b'src imagebuilder file:packages\noption check_signature\n'}
        contexts = {'build_dir/linux/.config': b'kernel config', 'build_dir/linux/Image': b'kernel image',
                    'build_dir/linux/board.dtb': b'device tree',
                    'tmp/.targetinfo': b'target', 'tmp/.packageinfo': b'packages'}
        self.files.update(contexts)
        metadata = {'schema_version': 1, 'identity': {'build_id': self.proof['build_id'],
                    'source_commit': self.proof['source_commit'], 'kernel_version': self.proof['kernel_version'],
                    'architecture': 'aarch64_cortex-a53', 'target': 'mediatek/filogic'},
                    'public_key_sha256': self.proof['public_key_sha256'],
                    'context': [{'path': path, 'size': len(data), 'sha256': digest(data)} for path, data in contexts.items()]}
        self.files['ax6000-imagebuilder.json'] = json.dumps(metadata).encode()
        self.proof['attestation_sha256'] = digest(self.files['ax6000-imagebuilder.json'])
        self.archive = self.make_archive(self.files)
        self.proof.update(archive_sha256=image.sha256(self.archive), archive_size=self.archive.stat().st_size)
        self.profile = self.root / 'profile.json'
        self.profile.write_text(json.dumps({'build_id': self.proof['build_id'], 'asu': {'enabled': True},
            'firmware': {'commit': self.proof['source_commit'], 'kernel_version': self.proof['kernel_version'],
                         'target': 'mediatek', 'subtarget': 'filogic', 'architecture': 'aarch64_cortex-a53'},
            'imagebuilder': {'sha256': self.proof['archive_sha256'], 'size': self.proof['archive_size']}}))
        self.proof['profile_sha256'] = image.sha256(self.profile)
        self.proof_file = self.root / 'reviewed-receipt.json'
        self.write_proof()

    def make_archive(self, files, additional=()):
        output = self.root / ('ib-' + str(len(list(self.root.glob('ib-*')))) + '.tar')
        with tarfile.open(output, 'w') as tar:
            for name, data in files.items():
                member = tarfile.TarInfo('imagebuilder/' + name)
                member.mode, member.size = 0o644, len(data)
                tar.addfile(member, io.BytesIO(data))
            for member in additional:
                tar.addfile(member)
        return output

    def write_proof(self):
        self.proof_file.write_text(json.dumps(self.proof))
        self.proof_sha = image.sha256(self.proof_file)

    def validate(self):
        return image.validate_inputs(self.archive, self.proof['archive_sha256'], self.proof_file,
                                     self.proof_sha, self.profile, self.key)

    def test_validated_fixture_does_not_invoke_docker(self):
        args = ['--archive', str(self.archive), '--archive-sha256', self.proof['archive_sha256'],
                '--verification-receipt', str(self.proof_file), '--verification-receipt-sha256', self.proof_sha,
                '--profile', str(self.profile), '--public-key', str(self.key)]
        with patch.object(image, 'docker') as docker, patch('sys.stdout', new_callable=io.StringIO) as output:
            image.main(args)
            result = json.loads(output.getvalue())
        docker.assert_not_called()
        self.assertTrue(result['validated'])
        self.assertFalse(result['image_built'])
        self.assertFalse(result['image_loaded'])

    def test_archive_proof_profile_and_public_key_hash_mismatch_fail_closed(self):
        self.validate()
        for target in [self.archive, self.profile, self.key, self.proof_file]:
            before = target.read_bytes()
            target.write_bytes(before + b'changed')
            with self.assertRaises(ValueError):
                self.validate()
            target.write_bytes(before)

    def test_unapproved_or_cross_cohort_generation_rejected(self):
        for field, wrong in [('approved', False), ('source_context_verified', False),
                             ('native_bank_verified', False), ('signatures_verified', False),
                             ('private_keys_absent', False), ('source_commit', 'd' * 40),
                             ('kernel_version', '6.12.1~' + 'b' * 32 + '-r1'),
                             ('cohort', '612-latest'), ('profiles', ['foreign'])]:
            with self.subTest(field=field):
                old = self.proof[field]
                self.proof[field] = wrong
                self.write_proof()
                with self.assertRaises(ValueError):
                    self.validate()
                self.proof[field] = old
                self.write_proof()

    def test_archive_escape_alias_and_special_files_rejected(self):
        for name, kind, target in [('imagebuilder/../../escape', tarfile.DIRTYPE, ''),
                                   ('imagebuilder/link', tarfile.SYMTYPE, '/etc/passwd'),
                                   ('imagebuilder/link', tarfile.SYMTYPE, '../../outside'),
                                   ('imagebuilder/device', tarfile.CHRTYPE, '')]:
            member = tarfile.TarInfo(name)
            member.type, member.linkname = kind, target
            archive = self.make_archive(self.files, [member])
            with self.assertRaises((ValueError, tarfile.TarError)):
                image.unpack(archive, self.root / 'rejected')
        link = tarfile.TarInfo('imagebuilder/alias')
        link.type, link.linkname = tarfile.SYMTYPE, 'build_dir'
        child = tarfile.TarInfo('imagebuilder/alias/new-file')
        archive = self.make_archive(self.files, [link, child])
        with self.assertRaises(ValueError):
            image.unpack(archive, self.root / 'rejected')

    def test_private_key_names_markers_and_changed_context_rejected(self):
        for name, contents in [('key-build', b'secret'), ('innocent.txt', b'-----BEGIN OPENSSH PRIVATE KEY-----'),
                               ('other.txt', b'untrusted comment: usign secret key\n'),
                               ('arbitrary.txt', b'untrusted comment: misleading public label\n' + base64.b64encode(b'EdBK' + b'k' * 100) + b'\n'),
                               ('build_dir/linux/Image', b'mismatching kernel')]:
            files = dict(self.files)
            files[name] = contents
            archive = self.make_archive(files)
            with tempfile.TemporaryDirectory(dir=self.root) as work:
                tree = image.unpack(archive, Path(work) / 'unpacked')
                with self.assertRaises(ValueError):
                    image.scan_tree(tree, self.proof)

    def test_usign_private_format_detection_does_not_reject_public_key_or_signature(self):
        self.assertTrue(image.private_key_content(b'EdBK' + b'k' * 100))
        self.assertFalse(image.private_key_content(base64.b64encode(b'Ed' + b'k' * 40)))
        self.assertFalse(image.private_key_content(base64.b64encode(b'Ed' + b'k' * 72)))

    def test_safe_internal_symlinks_and_hardlinks_accepted(self):
        sym = tarfile.TarInfo('imagebuilder/Makefile.link')
        sym.type, sym.linkname = tarfile.SYMTYPE, 'Makefile'
        hard = tarfile.TarInfo('imagebuilder/Makefile.hard')
        hard.type, hard.linkname = tarfile.LNKTYPE, 'imagebuilder/Makefile'
        tree = image.unpack(self.make_archive(self.files, [sym, hard]), self.root / 'unpacked')
        self.assertEqual((tree / 'Makefile.hard').read_bytes(), self.files['Makefile'])
        image.scan_tree(tree, self.proof)

    def test_apk_attestation_requires_package_manager_in_identity(self):
        proof = copy.deepcopy(self.proof)
        proof['package_manager'] = 'apk'
        files = dict(self.files)
        files['repositories'] = b'file:packages\n'
        metadata = json.loads(files['ax6000-imagebuilder.json'])
        metadata['identity']['package_manager'] = 'apk'
        files['ax6000-imagebuilder.json'] = json.dumps(metadata).encode()
        proof['attestation_sha256'] = digest(files['ax6000-imagebuilder.json'])
        tree = image.unpack(self.make_archive(files), self.root / 'apk-unpacked')
        image.scan_tree(tree, proof)
        metadata['identity'].pop('package_manager')
        (tree / 'ax6000-imagebuilder.json').write_text(json.dumps(metadata))
        proof['attestation_sha256'] = image.sha256(tree / 'ax6000-imagebuilder.json')
        with self.assertRaises(ValueError):
            image.scan_tree(tree, proof)

    def test_copy_only_recipe_and_result_layers_are_bound_to_base(self):
        recipe = image.recipe(self.proof, self.proof_sha)
        self.assertNotIn('\nRUN ', recipe)
        self.assertNotIn('\nADD ', recipe)
        self.assertIn('COPY --chown=1000:1000 builder/ /builder/', recipe)
        base = {'Id': image.BASE_IMAGE, 'RootFS': {'Layers': ['sha256:base']}}
        result = {'Id': 'sha256:' + 'd' * 64, 'RootFS': {'Layers': ['sha256:base', 'sha256:copy']},
                  'Config': {'User': '1000:1000', 'WorkingDir': '/builder', 'Entrypoint': [],
                             'Cmd': ['sleep', '86400'], 'Labels': image.labels(self.proof, self.proof_sha)}}
        image.validate_image(base, result, image.labels(self.proof, self.proof_sha))
        for modified in [result | {'RootFS': {'Layers': ['sha256:foreign', 'sha256:copy']}},
                         result | {'RootFS': {'Layers': ['sha256:base', 'sha256:run', 'sha256:copy']}}]:
            with self.assertRaises(ValueError):
                image.validate_image(base, modified, image.labels(self.proof, self.proof_sha))
        changed = copy.deepcopy(result)
        changed['Config']['User'] = 'root'
        with self.assertRaises(ValueError):
            image.validate_image(base, changed, image.labels(self.proof, self.proof_sha))
        changed = copy.deepcopy(result)
        changed['Config']['Labels'][image.LABEL_PREFIX + 'archive-sha256'] = '0' * 64
        with self.assertRaises(ValueError):
            image.validate_image(base, changed, image.labels(self.proof, self.proof_sha))

    def test_build_refuses_changed_base_before_any_engine_mutation(self):
        changed_base = {'Id': 'sha256:' + '0' * 64, 'Config': {}, 'RootFS': {'Layers': []}}
        with patch.object(image, 'inspect_image', return_value=changed_base), patch.object(image, 'docker') as docker:
            with self.assertRaises(ValueError):
                image.build_load(self.root, self.proof, self.proof_sha, self.root / 'fresh-output')
        docker.assert_not_called()
        self.assertFalse((self.root / 'fresh-output').exists())

    def test_rootless_client_uses_explicit_socket_and_never_mounts_production_socket(self):
        with patch.object(image, 'docker') as docker:
            docker.return_value.stdout = '{}'
            image.rootless_client(['image', 'inspect', 'sha256:' + 'a' * 64])
        command = docker.call_args.args[0]
        self.assertIn('--user=2000:2000', command)
        self.assertIn('--network=none', command)
        self.assertIn('--cap-drop=ALL', command)
        self.assertIn('--security-opt=no-new-privileges', command)
        self.assertIn('--memory=2g', command)
        self.assertIn('--memory-swap=2g', command)
        self.assertIn(image.BASE_IMAGE, command)
        self.assertIn(image.ROOTLESS_ENGINE, command)
        self.assertFalse(any('/var/run/docker.sock' in part for part in command))
        self.assertTrue(any(image.ROOTLESS_SOCKET in part for part in command))
        self.assertIn('name=rootless', image.CLIENT_GUARD)
        self.assertIn('"$id" = "$1"', image.CLIENT_GUARD)

    def test_docker_client_environment_cannot_select_ambient_context(self):
        ambient = {'DOCKER_HOST': 'tcp://wrong', 'DOCKER_CONTEXT': 'production', 'DOCKER_API_VERSION': '1.1'}
        with patch.dict(os.environ, ambient), patch.object(image, 'checked_run') as run:
            image.docker(['info'])
        self.assertEqual(run.call_args.args[0][:3], ['/usr/bin/docker', '--host', image.ROOTFUL_SOCKET])
        self.assertFalse(set(ambient) & set(run.call_args.kwargs['env']))


if __name__ == '__main__':
    unittest.main()
