import base64
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
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

    def test_vendor_exception_inventory_rejects_unknown_or_incomplete_approvals(self):
        entry = copy.deepcopy(image.PUBLIC_VENDOR_TOOL)
        self.assertEqual(image.reviewed_vendor_tools(self.proof | {'reviewed_public_vendor_tools': [entry]}),
                         {entry['path']: entry})
        invalid = [None, {}, [entry, entry], [entry | {'path': 'staging_dir/host/bin/other-tool'}],
                   [entry | {'sha256': '0' * 64}], [entry | {'size': entry['size'] + 1}],
                   [entry | {'classification': 'signing-credential'}], [entry | {'source_commit': '0' * 40}],
                   [entry | {'source_header_sha256': '0' * 64}], [entry | {'source_implementation_sha256': '0' * 64}],
                   [{key: value for key, value in entry.items() if key != 'source_repository'}],
                   [entry | {'public_key_blocks': 6}], [entry | {'allow_all_keys': True}]]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                image.reviewed_vendor_tools(self.proof | {'reviewed_public_vendor_tools': value})

    def test_vendor_record_requires_its_exact_cohort_and_rejects_unmeasured_612(self):
        entry = copy.deepcopy(image.PUBLIC_VENDOR_TOOL)
        for cohort in (None, '612-recommended', '612-latest', 'unknown'):
            with self.subTest(cohort=cohort), self.assertRaisesRegex(ValueError, 'cohort'):
                image.reviewed_vendor_tools({'cohort': cohort, 'reviewed_public_vendor_tools': [entry]})
        self.assertEqual(image.reviewed_vendor_tools({'cohort': '612-latest'}), {})
        # Known research identities are not approvals of a new portable IB.
        for cohort, size, sha256 in (
                ('612-recommended', 1708336,
                 'eb4947b1a2cfe6c8862295f6decf7699aa1ef0aadcb59126f1c01ca92894ac08'),
                ('612-latest', 1493272,
                 'cd61cb05012bfddd79a88a3ddf0b072d201d43b9676c187d409dbd423157be57')):
            candidate = entry | {'size': size, 'sha256': sha256,
                'source_commit': '6a87eaf434cb89d4eba0b811a4b5d158fd9c519f',
                'source_header_sha256': '1455ab4366e869ea7afe3fecbe8b20baa5c9a2c105dc18c6e3dc9bfc55483e87',
                'source_implementation_sha256': 'b9ee120c68b3d1ea2f479ee15f646a0aa3343aa36a92db7a4d647cf91bad43b3',
                'public_key_blocks': 6}
            with self.subTest(unapproved_research_cohort=cohort), self.assertRaises(ValueError):
                image.reviewed_vendor_tools({'cohort': cohort, 'reviewed_public_vendor_tools': [candidate]})

    def test_future_612_record_is_only_a_synthetic_fixture_and_uses_its_own_size(self):
        # This is deliberately not a real vendor executable or a production
        # record. The larger fixture catches accidental use of the 6.6 bound.
        blob = bytearray(b'\x7fELF\x02\x01\x01' + b'\0' * (image.PUBLIC_VENDOR_TOOL['size'] + 1))
        blob[18:20] = b'\x3e\x00'
        blob = bytes(blob)
        entry = image.PUBLIC_VENDOR_TOOL | {'sha256': digest(blob), 'size': len(blob),
            'source_commit': '6a87eaf434cb89d4eba0b811a4b5d158fd9c519f',
            'source_header_sha256': '1455ab4366e869ea7afe3fecbe8b20baa5c9a2c105dc18c6e3dc9bfc55483e87',
            'source_implementation_sha256': 'b9ee120c68b3d1ea2f479ee15f646a0aa3343aa36a92db7a4d647cf91bad43b3',
            'public_key_blocks': 6}
        path = self.root / 'synthetic-future-vendor-tool.bin'
        path.write_bytes(blob)
        proof = {'cohort': '612-recommended', 'reviewed_public_vendor_tools': [entry]}
        with self.assertRaises(ValueError):
            image.reviewed_vendor_tools(proof)
        with self.assertRaises(ValueError):
            image.verify_reviewed_vendor_tool(path, entry)
        fixture_records = (*image.REVIEWED_PUBLIC_VENDOR_TOOLS, ('612-recommended', entry))
        with patch.object(image, 'REVIEWED_PUBLIC_VENDOR_TOOLS', fixture_records):
            self.assertEqual(image.reviewed_vendor_tools(proof), {entry['path']: entry})
            image.verify_reviewed_vendor_tool(path, entry)
            for cohort in ('66', '612-latest', None):
                with self.subTest(cohort=cohort), self.assertRaises(ValueError):
                    image.reviewed_vendor_tools(proof | {'cohort': cohort})
            for field, value in [('size', len(blob) - 1), ('sha256', '0' * 64),
                                 ('source_commit', '0' * 40), ('source_header_sha256', '0' * 64),
                                 ('public_key_blocks', 5), ('path', 'staging_dir/host/bin/dlink-sge-image')]:
                with self.subTest(field=field), self.assertRaises(ValueError):
                    image.reviewed_vendor_tools(proof | {'reviewed_public_vendor_tools': [entry | {field: value}]})
            for bad_blob in (blob + b'!', blob[:-1], blob[:-1] + b'!', b'!' + blob[1:]):
                path.write_bytes(bad_blob)
                with self.assertRaises(ValueError):
                    image.verify_reviewed_vendor_tool(path, entry)

    def test_recommended_portable_record_is_literal_and_latest_remains_unapproved(self):
        entry = copy.deepcopy(image.RECOMMENDED_PUBLIC_VENDOR_TOOL)
        proof = {'cohort': '612-recommended', 'reviewed_public_vendor_tools': [entry]}
        self.assertEqual(image.reviewed_vendor_tools(proof), {entry['path']: entry})
        for cohort in ('66', '612-latest', None):
            with self.subTest(cohort=cohort), self.assertRaises(ValueError):
                image.reviewed_vendor_tools(proof | {'cohort': cohort})
        for field, value in [('size', entry['size'] + 1), ('sha256', '0' * 64),
                             ('public_key_blocks', 5), ('public_key_blocks', 7),
                             ('source_commit', '0' * 40), ('source_header_sha256', '0' * 64),
                             ('source_implementation_sha256', '0' * 64),
                             ('path', 'staging_dir/host/bin/dlink-sge-image')]:
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                image.reviewed_vendor_tools(proof | {'reviewed_public_vendor_tools': [entry | {field: value}]})
        self.assertEqual(image.PUBLIC_VENDOR_TOOL['sha256'],
                         'e1cc6b5b30c14f31017b4d2c460fe5642be18a6a36f50fb9d690711920ea1dbf')
        self.assertEqual(image.PUBLIC_VENDOR_TOOL['size'], 1857584)
        self.assertEqual(image.PUBLIC_VENDOR_TOOL['public_key_blocks'], 5)

    def test_actual_recommended_portable_elf_and_wrapper_when_available(self):
        default = Path('/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/vendor612-payload-measurement-v2/actual-recommended/result')
        fixture = Path(os.environ.get('BUILDER_TEST_REC_VENDOR_TOOL', default / 'portable-vendor-elf.bin'))
        wrapper_fixture = Path(os.environ.get('BUILDER_TEST_REC_VENDOR_WRAPPER', default / 'portable-wrapper.txt'))
        if not fixture.is_file() or not wrapper_fixture.is_file():
            self.skipTest('Set BUILDER_TEST_REC_VENDOR_TOOL/WRAPPER to independently measured portable files')
        blob, wrapper = fixture.read_bytes(), wrapper_fixture.read_bytes()
        entry = image.RECOMMENDED_PUBLIC_VENDOR_TOOL
        self.assertEqual(len(blob), 1491024)
        self.assertEqual(digest(blob), '6d84f24ff78aaa1155d5286787256dac07229c05cbce1d16376a7314d5236ef6')
        self.assertEqual(len(wrapper), 236)
        self.assertEqual(digest(wrapper), '5b57f0df74b479682186a0e6f9ea7215d0ccab060377a351296684762ccf93e9')
        blocks = re.findall(rb'-----BEGIN RSA PRIVATE KEY-----.*?-----END RSA PRIVATE KEY-----(?:\r?\n)?', blob, re.S)
        self.assertEqual(len(blocks), 6)
        self.assertEqual({digest(block) for block in blocks}, {
            '18394093ed2e8b8cdcd57b2fe2f1a48ba53ecfbc1119925e9368679677551bc2',
            'bfb46a3e732cc02ba09f4e0047f2a46d3052fb3c1169db786e2db427864c431f',
            '9638296ecc28bc6814843c82e3b7dd9e8681ec1a016a56d8a6df46c55f561a0b',
            '369b70cb06c2d5cfb26101fc2c3110f97cc96d4cf2307e2c79112f1718505019',
            'ecaff8d72ddec294aaf3654f1da9c1664054ff15d892728b646dd4944ad95dd5',
            'e4c333f98cb7e0179cd64106df9d204b585884e28c83cdb9ebeadbacc1c4a1ac'})
        path = self.root / entry['path']
        path.parent.mkdir(parents=True)
        path.write_bytes(blob)
        visible = path.with_name('dlink-sge-image')
        visible.write_bytes(wrapper)
        image.verify_reviewed_vendor_tool(path, entry)
        for bad in (blob[:-1] + bytes([blob[-1] ^ 1]), blob[:-1], blob + blocks[0]):
            path.write_bytes(bad)
            with self.assertRaises(ValueError):
                image.verify_reviewed_vendor_tool(path, entry)
        path.write_bytes(blob)
        for bad in (wrapper[:-1] + b'!', wrapper + b'!', b'-----BEGIN OPENSSH PRIVATE KEY-----'):
            visible.write_bytes(bad)
            with self.assertRaises(ValueError):
                image.verify_reviewed_vendor_tool(path, entry)
        visible.unlink()
        with self.assertRaises(ValueError):
            image.verify_reviewed_vendor_tool(path, entry)
        visible.symlink_to(wrapper_fixture)
        with self.assertRaises(ValueError):
            image.verify_reviewed_vendor_tool(path, entry)

    def test_vendor_exception_requires_reapproved_receipt_digest(self):
        self.proof['reviewed_public_vendor_tools'] = [copy.deepcopy(image.PUBLIC_VENDOR_TOOL)]
        self.proof_file.write_text(json.dumps(self.proof))
        with self.assertRaisesRegex(ValueError, 'receipt hash differs'):
            self.validate()

    def test_public_vendor_fixture_exception_is_exact_and_cannot_hide_other_secrets(self):
        # A deliberately synthetic ELF/key marker exercises the exact-byte gate;
        # production constants remain pinned to the independently reviewed blob.
        public_fixture = bytearray(b'\x7fELF\x02\x01\x01' + b'\0' * 13)
        public_fixture[18:20] = b'\x3e\x00'
        public_fixture = bytes(public_fixture) + b'\n-----BEGIN RSA PRIVATE KEY-----\nSYNTHETIC PUBLIC FACTORY FIXTURE\n'
        entry = copy.deepcopy(image.PUBLIC_VENDOR_TOOL)
        entry.update(sha256=digest(public_fixture), size=len(public_fixture))
        proof = self.proof | {'reviewed_public_vendor_tools': [entry]}
        files = self.files | {entry['path']: public_fixture}
        with patch.object(image, 'REVIEWED_PUBLIC_VENDOR_TOOLS', (('66', entry),)):
            tree = image.unpack(self.make_archive(files), self.root / 'vendor-unpacked')
            result = image.scan_tree(tree, proof)
            self.assertEqual(result['reviewed_public_vendor_tools'], [entry])
            with self.assertRaisesRegex(ValueError, 'Private key marker'):
                image.scan_tree(tree, self.proof)
            path = tree / entry['path']
            for bad in (public_fixture + b'-----BEGIN OPENSSH PRIVATE KEY-----', public_fixture[:-1] + b'!'):
                path.write_bytes(bad)
                with self.assertRaises(ValueError):
                    image.scan_tree(tree, proof)
                path.write_bytes(public_fixture)
            for name, contents in [('other-tool.bin', public_fixture), ('key-build', b'native secret'),
                                   ('innocent.txt', b'-----BEGIN OPENSSH PRIVATE KEY-----'),
                                   ('staging_dir/host/bin/dlink-sge-image', public_fixture)]:
                other = tree / name
                other.write_bytes(contents)
                with self.assertRaises(ValueError):
                    image.scan_tree(tree, proof)
                other.unlink()
            path.unlink()
            with self.assertRaises(ValueError):
                image.scan_tree(tree, proof)

    def test_actual_reviewed_public_vendor_elf_when_available(self):
        default = '/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21/native66/ib-verification/expanded/immortalwrt-imagebuilder-mediatek-filogic.Linux-x86_64/' + image.PUBLIC_VENDOR_TOOL['path']
        path = Path(os.environ.get('BUILDER_TEST_PUBLIC_VENDOR_TOOL', default))
        if not path.is_file():
            self.skipTest('Set BUILDER_TEST_PUBLIC_VENDOR_TOOL to the independently reviewed upstream ELF')
        image.verify_reviewed_vendor_tool(path, image.PUBLIC_VENDOR_TOOL)
        self.assertEqual(image.sha256(path), image.PUBLIC_VENDOR_TOOL['sha256'])

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

    def saved_image_fixture(self):
        # Synthetic Docker/OCI transport fixture, never loaded into a daemon.
        def encoded(value):
            return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()

        layer = b'SYNTHETIC UNIT LAYER, NOT A LOADABLE ROOTFS'
        layer_id = 'sha256:' + digest(layer)
        config = encoded({'architecture': 'amd64', 'os': 'linux', 'rootfs': {'type': 'layers', 'diff_ids': [layer_id]}})
        config_id = 'sha256:' + digest(config)
        manifest = encoded({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.manifest.v1+json',
            'config': {'mediaType': 'application/vnd.oci.image.config.v1+json', 'digest': config_id, 'size': len(config)},
            'layers': [{'mediaType': 'application/vnd.oci.image.layer.v1.tar', 'digest': layer_id, 'size': len(layer)}]})
        manifest_id = 'sha256:' + digest(manifest)
        index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json', 'manifests': [
            {'mediaType': 'application/vnd.oci.image.manifest.v1+json', 'digest': manifest_id, 'size': len(manifest)}]}
        blob = lambda value: 'blobs/sha256/' + value.split(':', 1)[1]
        files = {blob(layer_id): layer, blob(config_id): config, blob(manifest_id): manifest,
                 'index.json': encoded(index), 'oci-layout': encoded({'imageLayoutVersion': '1.0.0'}),
                 'manifest.json': encoded([{'Config': blob(config_id), 'RepoTags': None, 'Layers': [blob(layer_id)]}])}
        return files, config_id, manifest_id, [layer_id]

    def write_saved_image(self, files, extra=()):
        target = self.root / ('saved-' + str(len(list(self.root.glob('saved-*')))) + '.tar')
        with tarfile.open(target, 'w') as archive:
            for name, data in list(files.items()) + list(extra):
                entry = tarfile.TarInfo(name)
                entry.size = len(data)
                archive.addfile(entry, io.BytesIO(data))
        return target

    def test_cross_store_ids_must_both_derive_from_exact_verified_saved_image(self):
        files, config_id, manifest_id, layers = self.saved_image_fixture()
        saved = image.saved_image_identity(self.write_saved_image(files), config_id, layers)
        self.assertEqual(saved['config_id'], config_id)
        self.assertEqual(saved['oci_manifest_id'], manifest_id)
        self.assertEqual(saved['oci_manifest_sha256'], manifest_id.split(':')[1])
        for value in (config_id, manifest_id):
            self.assertEqual(image.loaded_image_id('Loaded image ID: ' + value + '\n', saved), value)
        for output in ('', 'Loaded image ID: sha256:' + '0' * 64 + '\n', 'Loaded image: moving:tag\n',
                       'Loaded image ID: ' + manifest_id + '\nError unpacking image: failed\n',
                       'Loaded image ID: ' + config_id + '\nLoaded image ID: ' + manifest_id + '\n'):
            with self.assertRaises(ValueError):
                image.loaded_image_id(output, saved)

    def test_saved_image_rejects_tampered_blobs_config_layers_and_multiple_manifests(self):
        files, config_id, manifest_id, layers = self.saved_image_fixture()
        for name in [key for key in files if key.startswith('blobs/')]:
            with self.subTest(blob=name), self.assertRaises(ValueError):
                image.saved_image_identity(self.write_saved_image(files | {name: files[name] + b'changed'}), config_id, layers)
        with self.assertRaises(ValueError):
            image.saved_image_identity(self.write_saved_image(files), 'sha256:' + '0' * 64, layers)
        with self.assertRaises(ValueError):
            image.saved_image_identity(self.write_saved_image(files), config_id, ['sha256:' + '0' * 64])
        for kind in ('multiple', 'wrong-size'):
            index = json.loads(files['index.json'])
            if kind == 'multiple':
                index['manifests'].append(copy.deepcopy(index['manifests'][0]))
            else:
                index['manifests'][0]['size'] += 1
            with self.assertRaises(ValueError):
                image.saved_image_identity(self.write_saved_image(files | {'index.json': json.dumps(index).encode()}), config_id, layers)
        with self.assertRaises(ValueError):
            image.saved_image_identity(self.write_saved_image(files | {'manifest.json': b'[]'}), config_id, layers)
        with self.assertRaises(ValueError):
            image.saved_image_identity(self.write_saved_image(files, [('index.json', files['index.json'])]), config_id, layers)
        with self.assertRaises(ValueError):
            image.saved_image_identity(self.write_saved_image(files | {'../../escape': b'unsafe'}), config_id, layers)

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
