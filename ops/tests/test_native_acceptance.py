"""Synthetic envelope guards only; these fixtures never approve a native build."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

FAILED = [
    'fa073e353536c6b3c6737e1d10e9af8c60e39b0ccda456e213ed2a609e4d9c91',
    '6455adfc386f748e8ea2b606f61d79c8959e8f00b300d0c6581c4539297174f3',
    'ff2b96386c10de3179678e20cb683428f57eb47546a149688dd85f21a283d6ae',
    '9ec62627c6bd7dc5df3826e09ad544134993ee857f607c199ef5faceb9c73e19',
    'd' * 64]  # Synthetic fifth terminal failure; never real R4 evidence.
FINAL = 'e' * 64  # Synthetic export-only process, never actual R4 evidence.
WORLD_PHASES = ('started.json', 'result.json', 'after-world.json', 'after-imagebuilder.json')
EXPORT_PHASES = ('started.json', 'result.json', 'after-imagebuilder.json', 'after-export.json')
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('rec_native_acceptance', ROOT / 'ops/native_acceptance.py')
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)
PROMOTE_SPEC = importlib.util.spec_from_file_location('acceptance_promoter', ROOT / 'ops/promote.py')
promote = importlib.util.module_from_spec(PROMOTE_SPEC)
PROMOTE_SPEC.loader.exec_module(promote)


def record(path):
    return {'path': str(path), 'size': path.stat().st_size,
            'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data))
    return record(path)


class NativeAcceptanceContracts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.source = self.root / 'source'; self.raw = self.root / 'raw'
        self.source.mkdir(); self.raw.mkdir()
        self.profile = {'channel': 'recommended', 'package_manager': 'apk', 'build_id': 'synthetic-not-accepted',
                        'asu': {'cohort': '612-recommended', 'seed': acceptance.SEED},
                        'firmware': {'commit': acceptance.SOURCE, 'kernel_version': acceptance.ABI}}
        self.manifest = {'recipe_commit': acceptance.PRODUCER, 'source_commit': acceptance.SOURCE,
                         'kernel_version': acceptance.ABI, 'build_id': self.profile['build_id']}
        write(self.raw / 'profile.json', self.profile); write(self.raw / 'lock.json', {'fixture': True})
        write(self.raw / 'firmware-manifest.json', self.manifest)
        (self.raw / 'build.config').write_bytes(b'SYNTHETIC CONFIG, NOT NATIVE EVIDENCE\n')
        roles = {}
        for role in acceptance.ROLES:
            path = self.source / ('kernel/Image' if role == 'KDIR/Image' else 'kernel/linux/' + role)
            path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(('SYNTHETIC ' + role).encode())
            roles[role] = {'path': path.relative_to(self.source).as_posix(),
                           **{k: v for k, v in record(path).items() if k != 'path'}}
        self.image = {k: roles['KDIR/Image'][k] for k in ('sha256', 'size')}
        old_image = {'sha256': 'a' * 64, 'size': self.image['size']}
        original = {'required_files': copy.deepcopy(roles)}
        original['required_files']['KDIR/Image'].update(old_image)
        original_ref = write(self.root / 'original.json', original)
        relation_ref = write(self.root / 'relation.json', {
            'kind': 'ax6000-specific-build-id-only-Image-relation-v1',
            'old_Image': old_image, 'new_Image': self.image})
        context = {'schema_version': 2, 'kind': 'ax6000-accepted-native-kernel-context-v2',
                   'source_commit': acceptance.SOURCE, 'recipe_commit': acceptance.PRODUCER,
                   'kernel_abi': acceptance.ABI, 'cohort': '612-recommended',
                   'required_files': roles, 'original_context': original_ref, 'transition_proof': relation_ref,
                   'history': {'failed_containers': {'original_failed_id': FAILED[0], 'xxd_resume_failed_id': FAILED[1]}},
                   'prior_native_image_byte_identical': False, 'prior_native_abi_context_byte_identical': True}
        context_ref = write(self.root / 'context.json', context)
        enrollment_ref = write(self.root / 'enrollment.json', {
            'schema_version': 1, 'kind': 'ax6000-rec-accepted-functional-context-v1', 'approved': True,
            'recipe_commit': acceptance.PRODUCER, 'source_commit': acceptance.SOURCE,
            'accepted_context_sha256': context_ref['sha256'], 'transition_proof_sha256': relation_ref['sha256'],
            'original_context_sha256': original_ref['sha256'], 'root_independently_recomputed_relation': True,
            'all_future_context_checks_complete_byte_exact': True,
            'prior_native_image_byte_identical': False, 'prior_native_abi_context_byte_identical': True})
        self.native = {'ok': True, 'channel': 'recommended', 'package_manager': 'apk',
                       'source_commit': acceptance.SOURCE, 'kernel_abi': acceptance.ABI,
                       'build_id': self.profile['build_id'], 'sysupgrade_input': self.image,
                       'layouts': {name: {'kernel': self.image} for name in acceptance.LAYOUTS}}
        self.native_path = self.root / 'native.json'; self.native_ref = write(self.native_path, self.native)
        strict = {name: {key: row[key] for key in ('sha256', 'size')} for name, row in roles.items()}
        self.completion = self.root / 'completion'
        self.completion_ref = write(self.completion / 'completion-manifest.json', {
            'kind': 'native-recommended-selected-ib-completion-v1', 'attempt_generation': 'R3',
            'history': {'original_failed_id': FAILED[0], 'xxd_resume_failed_id': FAILED[1],
                        'startup_mapping_failed_id': FAILED[2], 'prior_results_unchanged': True},
            'recipe_commit': acceptance.PRODUCER, 'source_commit': acceptance.SOURCE,
            'raw_output': str(self.raw)})
        for name in WORLD_PHASES:
            write(self.completion / 'output' / name, {'synthetic_phase': name})
        self.export = self.root / 'different-runner/export-only'
        self.export_ref = write(self.export / 'export-manifest.json', {'synthetic_export_plan': True})
        for name in EXPORT_PHASES:
            write(self.export / 'receipts' / name, {'synthetic_export_phase': name})
        failed_processes = []
        for index, pid in enumerate(FAILED):
            code = 2 if index < 2 else 1
            terminal = {'Id': pid, 'State': {'Status': 'exited', 'Running': False,
                                           'OOMKilled': False, 'ExitCode': code}}
            ref = write(self.root / 'history' / (str(index) + '.json'), terminal if index % 2 else [terminal])
            failed_processes.append({'producer_id': pid, 'process_exit_code': code, 'inspect': ref})
        inputs = [*(Path(row['inspect']['path']) for row in failed_processes),*(self.raw / name for name in ('profile.json', 'lock.json', 'firmware-manifest.json', 'build.config')),
                  self.source / 'kernel/linux/.config', self.completion / 'completion-manifest.json',
                  *(self.completion / 'output' / name for name in WORLD_PHASES),
                  self.export / 'export-manifest.json',
                  *(self.export / 'receipts' / name for name in EXPORT_PHASES),
                  self.root / 'context.json', self.root / 'enrollment.json', self.root / 'relation.json']
        # V4 retains authenticated terminal history, four RAW files and ten separate stage files.
        write(self.root / 'completion-binding.json', {'synthetic': True})
        inputs.append(self.root / 'completion-binding.json')
        self.status = {'schema_version': 2, 'kind': 'ax6000-native-completion-acceptance-v2', 'ok': True,
                       'channel': 'recommended', 'cohort': '612-recommended', 'package_manager': 'apk',
                       'producer_commit': acceptance.PRODUCER, 'source_commit': acceptance.SOURCE,
                       'seed': acceptance.SEED, 'kernel_abi': acceptance.ABI, 'build_id': self.profile['build_id'],
                       'container_exit_code': 0, 'oom_killed': False, 'all_layouts_verified': True,
                       'strict_accepted_context_unchanged': True, 'prior_native_image_byte_identical': False,
                       'prior_native_abi_context_byte_identical': True, 'accepted_context': context_ref,
                       'root_enrollment': enrollment_ref, 'kernel_image_transition': relation_ref,
                       'accepted_kernel_image': self.image, 'evidence_sha256': self.native_ref['sha256'],
                       'native_evidence': self.native_ref, 'strict_context_before': strict, 'strict_context_after': strict,
                       'producer_chain': {'kind': 'ax6000-staged-native-producer-chain-v1',
                                          'failed_producer_ids': FAILED.copy(), 'failed_processes': failed_processes,
                                          'final_producer_id': FINAL,
                                          'final_exit_code': 0, 'strict_accepted_context_unchanged': True,
                                          'prior_native_image_byte_identical': False,
                                          'prior_native_abi_context_byte_identical': True,
                                          'stages': {
                                              'world_and_imagebuilder': {
                                                  'producer_id': FAILED[3], 'process_exit_code': 1,
                                                  'successful_steps': ['world', 'imagebuilder'],
                                                  'manifest': self.completion_ref,
                                                  'runtime_receipts': {name: record(self.completion / 'output' / name)
                                                                       for name in WORLD_PHASES}},
                                              'export': {
                                                  'producer_id': FINAL, 'process_exit_code': 0,
                                                  'successful_steps': ['imagebuilder-package', 'export'], 'manifest': self.export_ref,
                                                  'runtime_receipts': {name: record(self.export / 'receipts' / name)
                                                                       for name in EXPORT_PHASES}}}},
                       'raw': str(self.raw), 'source': str(self.source),
                       'native_input_records': {str(path): acceptance.record(path) for path in inputs},
                       'native_inputs': {name: {k: record(self.raw / name)[k] for k in ('sha256', 'size')}
                                         for name in ('profile.json', 'lock.json', 'firmware-manifest.json')}}
        self.path = self.root / 'status.json'
        # Only synthetic tests replace constants, keeping production approved pins
        # out of test fixtures and never producing actual acceptance evidence.
        pins = {'accepted_context': context_ref['sha256'], 'root_enrollment': enrollment_ref['sha256'],
                'kernel_image_transition': relation_ref['sha256']}
        mock = patch.multiple(acceptance, APPROVED_REFS=pins, ORIGINAL_CONTEXT_SHA=original_ref['sha256'],
                              NEW_IMAGE=self.image, OLD_IMAGE_SHA=old_image['sha256'],
                              COMPLETION_MANIFEST={k: self.completion_ref[k] for k in ('sha256', 'size')})
        mock.start(); self.addCleanup(mock.stop)

    def verify(self, **kwargs):
        write(self.path, self.status)
        args = dict(cohort='612-recommended', profile=self.profile, native=self.native,
                    native_evidence=self.native_path, native_evidence_sha256=self.native_ref['sha256'],
                    source=self.source, raw=self.raw, recipe_commit=acceptance.PRODUCER)
        args.update(kwargs)
        return acceptance.verify(self.path, record(self.path)['sha256'], **args)

    def test_exact_enrolled_context_actual_files_and_underlying_native_evidence(self):
        result = self.verify()
        self.assertEqual(result['native_acceptance_sha256'], record(self.path)['sha256'])
        self.assertFalse(result['prior_native_image_byte_identical'])
        self.assertEqual(result['accepted_kernel_image'], self.image)

    def test_changed_or_missing_acceptance_flags_never_approve(self):
        original = copy.deepcopy(self.status)
        for key, value in [('ok', False), ('kind', 'proposal-only'), ('producer_commit', 'f' * 40),
                           ('seed', 'e' * 64), ('kernel_abi', '6.12.1~wrong-r1'), ('all_layouts_verified', False),
                           ('strict_accepted_context_unchanged', False), ('prior_native_image_byte_identical', True),
                           ('prior_native_abi_context_byte_identical', False), ('container_exit_code', 1),
                           ('oom_killed', True), ('evidence_sha256', 'f' * 64)]:
            self.status = {**original, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError): self.verify()
        self.status = {**original, 'strict_base_context_unchanged': True}
        with self.assertRaises(ValueError): self.verify()

    def test_wrong_mode_missing_digest_and_changed_native_raw_are_rejected(self):
        for cohort in ('66', '612-latest'):
            with self.subTest(cohort=cohort), self.assertRaises(ValueError): self.verify(cohort=cohort)
        write(self.path, self.status)
        with self.assertRaises(ValueError):
            acceptance.verify(self.path, '0' * 64, cohort='612-recommended', profile=self.profile,
                              native=self.native, native_evidence=self.native_path,
                              native_evidence_sha256=self.native_ref['sha256'], source=self.source,
                              raw=self.raw, recipe_commit=acceptance.PRODUCER)
        (self.raw / 'lock.json').write_text('changed')
        with self.assertRaises(ValueError): self.verify()

    def test_complete_new_image_abi_context_and_all_layout_bytes_remain_exact(self):
        source_image = self.source / 'kernel/Image'; original = source_image.read_bytes()
        source_image.write_bytes(original[:-1] + b'!')
        with self.assertRaises(ValueError): self.verify()
        source_image.write_bytes(original)
        config = self.source / 'kernel/linux/.config'; original_config = config.read_bytes()
        config.write_bytes(original_config + b'changed')
        with self.assertRaises(ValueError): self.verify()
        config.write_bytes(original_config)
        self.native['layouts']['stock'] = {'kernel': {**self.image, 'sha256': 'b' * 64}}
        self.native_ref = write(self.native_path, self.native)
        self.status.update(native_evidence=self.native_ref, evidence_sha256=self.native_ref['sha256'])
        with self.assertRaises(ValueError): self.verify()

    def test_enrolled_references_are_explicit_immutable_and_not_links(self):
        original = copy.deepcopy(self.status)
        for role in acceptance.APPROVED_REFS:
            self.status = copy.deepcopy(original); self.status[role]['sha256'] = 'f' * 64
            with self.subTest(role=role), self.assertRaises(ValueError): self.verify()
        self.status = copy.deepcopy(original)
        context = Path(self.status['accepted_context']['path'])
        linked = context.with_name('context-link'); linked.symlink_to(context)
        self.status['accepted_context']['path'] = str(linked)
        with self.assertRaises(ValueError): self.verify()

    def test_four_raw_metadata_records_are_required_and_match_current_bytes(self):
        self.verify()
        original = copy.deepcopy(self.status)
        for name in ('profile.json', 'lock.json', 'firmware-manifest.json', 'build.config'):
            self.status = copy.deepcopy(original)
            self.status['native_input_records'].pop(str(self.raw / name))
            with self.subTest(missing_record=name), self.assertRaises(ValueError): self.verify()
        self.status = copy.deepcopy(original)
        path = self.raw / 'build.config'
        for change in ('missing', 'digest', 'size', 'alias', 'bytes', 'source', 'raw'):
            self.status = copy.deepcopy(original); before = path.read_bytes()
            records = self.status['native_input_records']
            if change == 'missing': records.pop(str(path))
            elif change == 'digest': records[str(path)]['sha256'] = '0' * 64
            elif change == 'size': records[str(path)]['size'] += 1
            elif change == 'alias': records[str(path.parent / 'child/../build.config')] = records.pop(str(path))
            elif change == 'bytes': path.write_bytes(before + b'changed')
            else: self.status[change] = str(self.root / 'different')
            with self.subTest(change=change), self.assertRaises(ValueError): self.verify()
            path.write_bytes(before)

    def test_both_stage_manifests_and_all_eight_receipts_bind_retained_files(self):
        self.verify()
        original = copy.deepcopy(self.status)
        for stage_name in ('world_and_imagebuilder', 'export'):
            stage = original['producer_chain']['stages'][stage_name]
            for name, ref in [('manifest', stage['manifest']), *stage['runtime_receipts'].items()]:
                path = Path(ref['path']); before = path.read_bytes()
                for change in ('missing-ref', 'wrong-ref', 'missing-input', 'wrong-input', 'changed-bytes', 'missing-file'):
                    self.status = copy.deepcopy(original)
                    changed = self.status['producer_chain']['stages'][stage_name]
                    refs = changed if name == 'manifest' else changed['runtime_receipts']
                    records = self.status['native_input_records']
                    if change == 'missing-ref': refs.pop(name)
                    elif change == 'wrong-ref': refs[name]['sha256'] = '0' * 64
                    elif change == 'missing-input': records.pop(str(path))
                    elif change == 'wrong-input': records[str(path)]['size'] += 1
                    elif change == 'missing-file': path.unlink()
                    else: path.write_bytes(before + b'changed')
                    with self.subTest(stage=stage_name, name=name, change=change), self.assertRaises(ValueError): self.verify()
                    path.write_bytes(before)

    def test_stage_success_never_claims_all_steps_ran_in_export_container(self):
        self.verify()
        original = copy.deepcopy(self.status)
        for stage_name, changes in (
                ('world_and_imagebuilder', {'process_exit_code': 0}),
                ('world_and_imagebuilder', {'successful_steps': ['world', 'imagebuilder', 'export']}),
                ('world_and_imagebuilder', {'producer_id': FINAL}),
                ('export', {'process_exit_code': 1}),
                ('export', {'successful_steps': ['world', 'imagebuilder', 'export']}),
                ('export', {'successful_steps': ['export']}),
                ('export', {'producer_id': FAILED[3]})):
            self.status = copy.deepcopy(original)
            self.status['producer_chain']['stages'][stage_name].update(changes)
            with self.subTest(stage=stage_name, changes=changes), self.assertRaises(ValueError): self.verify()
        for change in ('missing-stage', 'extra-stage', 'extra-phase', 'duplicate-ref', 'hash-only-ref', 'swapped-receipt', 'wrong-kind'):
            self.status = copy.deepcopy(original); chain = self.status['producer_chain']
            if change == 'missing-stage': chain['stages'].pop('export')
            elif change == 'extra-stage': chain['stages']['other'] = chain['stages']['export']
            elif change == 'wrong-kind': chain['kind'] = 'unstaged-producer-chain'
            else:
                refs = chain['stages']['export']['runtime_receipts']
                if change == 'extra-phase': refs['after-world.json'] = refs['result.json']
                elif change == 'duplicate-ref': refs['started.json'] = chain['stages']['world_and_imagebuilder']['runtime_receipts']['started.json']
                elif change == 'swapped-receipt': refs['started.json'], refs['result.json'] = refs['result.json'], refs['started.json']
                else: refs['started.json'].pop('path')
            with self.subTest(change=change), self.assertRaises(ValueError): self.verify()

    def test_missing_fourth_raw_or_export_receipt_cannot_claim_native_success(self):
        self.verify()
        for path in (self.raw / 'build.config', self.export / 'receipts/after-export.json'):
            before = path.read_bytes(); path.unlink()
            with self.subTest(missing_file=path.name), self.assertRaises(ValueError): self.verify()
            path.write_bytes(before)

    def test_authenticated_terminal_history_is_generic_and_retains_enrollment(self):
        self.verify()
        chain = self.status['producer_chain']; pid = 'f' * 64
        ref = write(self.root / 'history/later.json', {'Id': pid, 'State': {
            'Status': 'exited', 'Running': False, 'OOMKilled': False, 'ExitCode': 7}})
        chain['failed_processes'].append({'producer_id': pid, 'process_exit_code': 7, 'inspect': ref})
        chain['failed_producer_ids'].append(pid)
        self.status['native_input_records'][ref['path']] = {k: ref[k] for k in ('sha256', 'size')}
        self.verify()  # No fixed transient-attempt count or ID list in this consumer.

    def test_missing_forged_or_ambiguous_terminal_history_is_rejected(self):
        self.verify(); original = copy.deepcopy(self.status)
        for change in ('absent', 'empty', 'projection', 'duplicate', 'bool-exit', 'success-exit',
                       'wrong-id', 'wrong-exit', 'running', 'oom', 'wrong-status', 'missing-input',
                       'changed-input', 'aliased-ref', 'ambiguous-list', 'lost-enrollment'):
            self.status = copy.deepcopy(original); chain = self.status['producer_chain']
            row = chain['failed_processes'][0]; path = Path(row['inspect']['path']); before = path.read_bytes()
            terminal = json.loads(before)[0]
            if change == 'absent': chain.pop('failed_processes')
            elif change == 'empty': chain['failed_processes'] = []
            elif change == 'projection': chain['failed_producer_ids'].reverse()
            elif change == 'duplicate': chain['failed_processes'].append(copy.deepcopy(row))
            elif change == 'bool-exit': row['process_exit_code'] = True
            elif change == 'success-exit': row['process_exit_code'] = 0
            elif change == 'missing-input': self.status['native_input_records'].pop(str(path))
            elif change == 'changed-input': self.status['native_input_records'][str(path)]['size'] += 1
            elif change == 'aliased-ref': row['inspect'] = chain['failed_processes'][1]['inspect']
            elif change == 'lost-enrollment':
                chain['failed_processes'] = chain['failed_processes'][2:]
                chain['failed_producer_ids'] = chain['failed_producer_ids'][2:]
            else:
                if change == 'wrong-id': terminal['Id'] = '0' * 64
                elif change == 'wrong-exit': terminal['State']['ExitCode'] = 99
                elif change == 'running': terminal['State']['Running'] = True
                elif change == 'oom': terminal['State']['OOMKilled'] = True
                elif change == 'wrong-status': terminal['State']['Status'] = 'dead'
                ref = write(path, [terminal, terminal] if change == 'ambiguous-list' else terminal)
                row['inspect'] = ref
                self.status['native_input_records'][str(path)] = {k: ref[k] for k in ('sha256', 'size')}
            with self.subTest(change=change), self.assertRaises(ValueError): self.verify()
            path.write_bytes(before)

    def test_failed_or_historically_ambiguous_native_producer_chain_is_rejected(self):
        original = copy.deepcopy(self.status['producer_chain'])
        for changes in ({'final_exit_code': 1}, {'final_producer_id': 'a' * 64},
                        {'failed_producer_ids': FAILED[:2]},
                        {'failed_producer_ids': FAILED[:3]},
                        {'failed_producer_ids': FAILED[::-1]},
                        {'failed_producer_ids': [*FAILED[:2], 'd' * 64]},
                        {'final_producer_id': 'f' * 64}, {'strict_accepted_context_unchanged': False},
                        {'prior_native_image_byte_identical': True}):
            self.status['producer_chain'] = {**original, **changes}
            with self.subTest(changes=changes), self.assertRaises(ValueError): self.verify()


class OptionalAcceptanceContracts(unittest.TestCase):
    def test_existing_66_and_local_behavior_needs_no_optional_envelope(self):
        for cohort in ('66', '612-recommended', '612-latest'):
            self.assertFalse(promote.native_acceptance_options(SimpleNamespace(cohort=cohort)))

    def test_both_flags_and_exact_local_recommended_mode_are_required(self):
        options = dict(cohort='612-recommended', source=Path('/synthetic-source'),
                       native_acceptance=Path('/synthetic-envelope'), native_acceptance_sha256='a' * 64)
        self.assertTrue(promote.native_acceptance_options(SimpleNamespace(**options)))
        for changes in ({'native_acceptance': None}, {'native_acceptance_sha256': None},
                        {'native_acceptance_sha256': 'bad'}, {'cohort': '66'}, {'cohort': '612-latest'},
                        {'source': None}, {'hosted_context': Path('/hosted')}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                promote.native_acceptance_options(SimpleNamespace(**{**options, **changes}))


if __name__ == '__main__': unittest.main()
