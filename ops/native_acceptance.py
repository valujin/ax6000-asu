"""Optional operator-only acceptance of two exact reviewed REC generations.

The original enrolled schema2 route is retained. The b122 schema3 route requires
its independently reviewed successful status, actual evidence and RAW custody.
Candidates alone grant no acceptance; current whole Image/ABI contexts are exact.
"""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import re

NEW_CONTEXT_PRODUCER = 'b122c35046ab1c3cd03828aabd168bb35466e2c8'
NEW_CONTEXT_STATUS_SHA = 'e7bfbf6ad2698eb05718b0c379c81468b681a5f84b07161d9da252dcc979dbf6'

PRODUCER = 'ea6de11283a6d83728e50b4b9ced214761ecc1c0'
SOURCE = 'ae65e1de69971b5a2e3cf7e39390ee93f274d488'
SEED = 'ff3a83d4df51fbe2d952538fa020f71bbae650bc88fe636ee273f7828e3022ad'
ABI = '6.12.108~942ed17ba3e2c90bc1373619dd44dedc-r1'
APPROVED_REFS = {
    'accepted_context': '2d7dbf000444728dedd334a432445cf8aece08b2944e6d28e172d823490f8d15',
    'root_enrollment': 'c0b5ac9ba485f617662221dec2e9829772c4602f9091e0cda4297071d493cdea',
    'kernel_image_transition': '5f958f7cb6569f34ef3f02602c86e00c918ed8b53db1f80800d8e4d17b68a01a'}
ORIGINAL_CONTEXT_SHA = 'cddaaf6593c873326894003a3695b1083435447ba49556c744b0b0fd995fd87c'
OLD_IMAGE_SHA = 'ac19e2c554e40219aed043a0760aef2a609743ec0437d295c4f7f15f51886d8f'
NEW_IMAGE = {'sha256': '5a0eedece2116a8dd046bd8337b487bdfc6913eaf1465d3dc6b711d0851ad611', 'size': 14661640}
COMPLETION_MANIFEST = {'sha256': '3cf19fdab1809b3ce5e6f9b563f0194e873d3550ab450a784c87131010d72a9d', 'size': 13602}
STAGES = {
    'world_and_imagebuilder': {'exit_code': 1, 'steps': ['world', 'imagebuilder'],
                              'receipts': {'started.json', 'result.json', 'after-world.json', 'after-imagebuilder.json'}},
    'export': {'exit_code': 0, 'steps': ['imagebuilder-package', 'export'],
               'receipts': {'started.json', 'result.json', 'after-imagebuilder.json', 'after-export.json'}}}
ROLES = {'.config', '.vermagic', 'Module.symvers', 'include/config/kernel.release', 'KDIR/Image'}
LAYOUTS = {'stock', 'mtkuboot', 'ubootmod'}
SHA = re.compile(r'[0-9a-f]{64}')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def regular(path, cap=64 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts and path.is_file()
         and not any(item.is_symlink() for item in (path, *path.parents))
         and path.stat().st_size <= cap, 'Invalid native acceptance input: ' + str(path))
    return path


def record(path):
    path = regular(path)
    with path.open('rb') as stream:
        return {'sha256': hashlib.file_digest(stream, 'sha256').hexdigest(), 'size': path.stat().st_size}


def file_ref(item, pin=None):
    need(isinstance(item, dict) and set(item) == {'path', 'sha256', 'size'}
         and isinstance(item.get('path'), str) and isinstance(item.get('sha256'), str)
         and SHA.fullmatch(item['sha256']) and type(item.get('size')) is int
         and item['size'] >= 0, 'Invalid immutable native acceptance file reference')
    path = regular(item['path'])
    need(str(path) == item['path'] and record(path) == {key: item[key] for key in ('sha256', 'size')}
         and (pin is None or item['sha256'] == pin), 'Native acceptance reference bytes/SHA differ')
    return path


def read(path, *, object_only=True):
    def unique(items):
        data = {}
        for key, value in items:
            need(key not in data, 'Duplicate native acceptance JSON key')
            data[key] = value
        return data
    def constant(_):
        raise ValueError('Nonfinite native acceptance JSON')
    data = json.loads(regular(path, 32 * 1024**2).read_bytes(), object_pairs_hook=unique, parse_constant=constant)
    need(not object_only or isinstance(data, dict), 'Native acceptance JSON must be an object')
    return data


def new_context_module():
    spec = importlib.util.spec_from_file_location('operator_native_new_context',
                                                 Path(__file__).with_name('native_new_context.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_new_context(path, pin, *, cohort, profile, native, native_evidence,
                       native_evidence_sha256, raw, source, recipe_commit):
    context = new_context_module()
    need(cohort == '612-recommended' and recipe_commit == NEW_CONTEXT_PRODUCER
         and profile.get('channel') == 'recommended' and profile.get('package_manager') == 'apk'
         and profile.get('asu', {}).get('cohort') == cohort
         and profile['asu'].get('seed') == context.SEED
         and profile.get('firmware', {}).get('commit') == context.SOURCE
         and profile['firmware'].get('kernel_version') == context.ABI,
         'Schema3 acceptance is restricted to the exact b122 recommended APK producer')
    need(pin == NEW_CONTEXT_STATUS_SHA and record(path)['sha256'] == pin,
         'Exact independently reviewed schema3 native status SHA256 required')
    # Keep the normal strict JSON decoder, including duplicate-key refusal.
    envelope = read(path)
    status, candidate, _ = context.load_accepted(Path(path), pin)
    need(envelope == status and status.get('build_id') == profile['build_id'],
         'Schema3 native generation differs')
    raw, source = Path(raw).absolute(), Path(source).absolute()
    need(status['raw'] == str(raw) and status['source'] == str(source),
         'Schema3 actual source/RAW custody differs')
    evidence_path = file_ref(status['native_evidence'], native_evidence_sha256)
    need(evidence_path == Path(native_evidence).absolute() and read(evidence_path) == native
         and status['evidence_sha256'] == native_evidence_sha256
         and native.get('schema_version') == 1 and native.get('ok') is True
         and native.get('source_commit') == context.SOURCE and native.get('kernel_abi') == context.ABI
         and native.get('build_id') == profile['build_id'] and native.get('package_manager') == 'apk'
         and native.get('channel') == 'recommended' and set(native.get('layouts', {})) == LAYOUTS,
         'Schema3 underlying full native evidence differs')
    for kernel in [native.get('sysupgrade_input', {}), *(row.get('kernel', {}) for row in native['layouts'].values())]:
        need(all(kernel.get(k) == v for k, v in status['accepted_kernel_image'].items()),
             'Schema3 layout does not contain the exact complete new Image')
    need(status.get('sdk') == profile.get('sdk')
         and native.get('sdk_context', {}).get('sdk_sha256') == profile['sdk']['sha256']
         and native['sdk_context'].get('matching_contexts') == status['source_context7'],
         'Schema3 SDK archive or all-seven prepared contexts differ')
    # Approved helper retains all honest world/packaging failure custody and
    # compares whole owned/new and original/prior Image bytes plus ABI4/SDK7.
    for root, item in [(source, candidate['owned_context']),
                       (Path(status['original_source']), candidate['original_context'])]:
        for row in item['required_files'].values():
            relative = PurePosixPath(row['path'])
            need(not relative.is_absolute() and '..' not in relative.parts and str(relative) == row['path'],
                 'Unsafe schema3 source role path')
            regular(root / relative)
        for role in context.SEVEN:
            regular(root / context.KROOT / role)
    need(record(source / '.config') == record(raw / 'build.config'),
         'Schema3 outer source configuration differs from actual RAW build.config')
    context.source_contexts(status, candidate)
    need(read(raw / 'profile.json') == profile and set(status['native_inputs']) ==
         {'profile.json', 'lock.json', 'firmware-manifest.json'}
         and all(record(raw / name) == row for name, row in status['native_inputs'].items()),
         'Schema3 actual RAW input bytes differ')
    manifest = read(raw / 'firmware-manifest.json')
    need(manifest.get('recipe_commit') == NEW_CONTEXT_PRODUCER and manifest.get('source_commit') == context.SOURCE
         and manifest.get('build_id') == profile['build_id'] and manifest.get('kernel_version') == context.ABI,
         'Schema3 RAW producer/generation differs')
    baseline = read(file_ref(status['sdk_baseline']))
    need(baseline.get('schema_version') == 1 and baseline.get('package_manager') == 'apk'
         and baseline.get('source_commit') == context.SOURCE and baseline.get('kernel_version') == context.ABI,
         'Schema3 native SDK baseline identity differs')
    return {'native_acceptance_sha256': pin, 'native_acceptance_schema_version': 3,
            'strict_accepted_context_unchanged': False, 'strict_new_context_unchanged': True,
            'prior_image_equal': False, 'prior_abi_context_equal': True,
            'accepted_kernel_image': status['accepted_kernel_image'], 'prior_kernel_image': status['prior_kernel_image'],
            **{name + '_sha256': status[name]['sha256'] for name in
               ('candidate_context', 'world_success_custody', 'producer_completion')},
            'native_bank_sha256': status['native_bank_sha256']}


def verify(path, pin, *, cohort, profile, native, native_evidence, native_evidence_sha256,
           raw, source, recipe_commit):
    if recipe_commit == NEW_CONTEXT_PRODUCER:
        return verify_new_context(path, pin, cohort=cohort, profile=profile, native=native,
                                  native_evidence=native_evidence, native_evidence_sha256=native_evidence_sha256,
                                  raw=raw, source=source, recipe_commit=recipe_commit)
    need(cohort == '612-recommended' and recipe_commit == PRODUCER
         and profile.get('channel') == 'recommended' and profile.get('package_manager') == 'apk'
         and profile.get('asu', {}).get('cohort') == cohort
         and profile['asu'].get('seed') == SEED and profile.get('firmware', {}).get('commit') == SOURCE
         and profile['firmware'].get('kernel_version') == ABI,
         'Native acceptance is restricted to the exact frozen EA recommended APK producer')
    need(isinstance(pin, str) and SHA.fullmatch(pin) and record(path)['sha256'] == pin,
         'Explicit native acceptance envelope SHA256 differs')
    status = read(path)
    need(status.get('schema_version') == 2 and status.get('kind') == 'ax6000-native-completion-acceptance-v2'
         and status.get('ok') is True and status.get('all_layouts_verified') is True
         and type(status.get('container_exit_code')) is int and status['container_exit_code'] == 0
         and status.get('oom_killed') is False and 'strict_base_context_unchanged' not in status,
         'Successful unambiguous V2 native acceptance is required')
    expected = {'producer_commit': PRODUCER, 'source_commit': SOURCE, 'seed': SEED, 'kernel_abi': ABI,
                'channel': 'recommended', 'cohort': cohort, 'package_manager': 'apk', 'build_id': profile['build_id']}
    need(all(status.get(key) == value for key, value in expected.items()), 'Native acceptance generation differs')
    need(status.get('strict_accepted_context_unchanged') is True
         and status.get('prior_native_image_byte_identical') is False
         and status.get('prior_native_abi_context_byte_identical') is True,
         'Native acceptance must preserve the enrolled/original Image distinction')
    documents = {role: read(file_ref(status.get(role), digest)) for role, digest in APPROVED_REFS.items()}
    context, enrollment, relation = (documents[role] for role in ('accepted_context', 'root_enrollment', 'kernel_image_transition'))
    need(context.get('schema_version') == 2 and context.get('kind') == 'ax6000-accepted-native-kernel-context-v2'
         and context.get('source_commit') == SOURCE and context.get('recipe_commit') == PRODUCER
         and context.get('kernel_abi') == ABI and context.get('cohort') == cohort,
         'Enrolled native context generation differs')
    need(enrollment.get('kind') == 'ax6000-rec-accepted-functional-context-v1' and enrollment.get('approved') is True
         and enrollment.get('root_independently_recomputed_relation') is True
         and enrollment.get('all_future_context_checks_complete_byte_exact') is True
         and enrollment.get('recipe_commit') == PRODUCER and enrollment.get('source_commit') == SOURCE
         and enrollment.get('accepted_context_sha256') == APPROVED_REFS['accepted_context']
         and enrollment.get('transition_proof_sha256') == APPROVED_REFS['kernel_image_transition']
         and enrollment.get('original_context_sha256') == ORIGINAL_CONTEXT_SHA,
         'Explicit root enrollment differs')
    for document in (context, enrollment):
        need(document.get('prior_native_image_byte_identical') is False
             and document.get('prior_native_abi_context_byte_identical') is True,
             'Enrolled prior Image/ABI claims differ')
    chain = status.get('producer_chain', {})
    history = context.get('history', {}).get('failed_containers', {})
    need(isinstance(chain, dict) and chain.get('kind') == 'ax6000-staged-native-producer-chain-v1'
         and type(chain.get('final_exit_code')) is int and chain['final_exit_code'] == 0
         and isinstance(chain.get('final_producer_id'), str) and SHA.fullmatch(chain['final_producer_id'])
         and chain.get('strict_accepted_context_unchanged') is True
         and chain.get('prior_native_image_byte_identical') is False
         and chain.get('prior_native_abi_context_byte_identical') is True,
         'Successful native completion chain loses strict context or final process identity')
    original = read(file_ref(context['original_context'], ORIGINAL_CONTEXT_SHA))
    need(file_ref(context['transition_proof'], APPROVED_REFS['kernel_image_transition'])
         == file_ref(status['kernel_image_transition']), 'Enrolled relation reference differs')
    need(relation.get('kind') == 'ax6000-specific-build-id-only-Image-relation-v1'
         and relation.get('old_Image', {}).get('sha256') == OLD_IMAGE_SHA
         and all(relation.get('new_Image', {}).get(key) == value for key, value in NEW_IMAGE.items()),
         'Specific enrolled Image relation differs')
    roles = context.get('required_files', {})
    need(set(roles) == set(original.get('required_files', {})) == ROLES, 'Strict native context roles differ')
    expected_roles = {name: dict(row) for name, row in original['required_files'].items()}
    need(expected_roles['KDIR/Image']['sha256'] == OLD_IMAGE_SHA, 'Historical original Image differs')
    expected_roles['KDIR/Image'].update(NEW_IMAGE)
    need(roles == expected_roles, 'Enrolled context changes more than the exact complete Image reference')
    need(isinstance(status.get('raw'), str) and isinstance(status.get('source'), str),
         'Native acceptance actual RAW/source paths are required')
    source = Path(source).absolute()
    need(status['source'] == str(source) and status['raw'] == str(Path(raw).absolute()),
         'Native acceptance source/RAW custody paths differ')
    raw = Path(status['raw'])  # Final RAW identity comes from the approved successful receipt.
    actual = {}
    for name, item in roles.items():
        relative = PurePosixPath(item['path'])
        need(not relative.is_absolute() and '..' not in relative.parts and str(relative) == item['path'],
             'Unsafe enrolled native source path')
        actual[name] = record(source / item['path'])
        need(actual[name] == {key: item[key] for key in ('sha256', 'size')},
             'Complete accepted native context bytes differ: ' + name)
    need(actual['KDIR/Image'] == status.get('accepted_kernel_image') == NEW_IMAGE
         and status.get('strict_context_before') == status.get('strict_context_after') == actual,
         'Full new Image/strict native context evidence differs')
    evidence_path = file_ref(status.get('native_evidence'), native_evidence_sha256)
    need(evidence_path == Path(native_evidence).absolute() and read(evidence_path) == native
         and status.get('evidence_sha256') == native_evidence_sha256 and native.get('ok') is True
         and native.get('source_commit') == SOURCE and native.get('kernel_abi') == ABI
         and native.get('build_id') == profile['build_id'] and native.get('package_manager') == 'apk'
         and native.get('channel') == 'recommended'
         and set(native.get('layouts', {})) == LAYOUTS,
         'Native acceptance underlying evidence differs')
    for kernel in [native.get('sysupgrade_input', {}), *(row.get('kernel', {}) for row in native['layouts'].values())]:
        need(all(kernel.get(key) == value for key, value in NEW_IMAGE.items()),
             'Native layout does not contain the exact complete accepted Image')
    need(status.get('raw') == str(raw) and status.get('source') == str(source),
         'Native acceptance source/RAW custody paths differ')
    inputs = status.get('native_input_records', {})
    need(isinstance(inputs, dict) and all(isinstance(name, str) for name in inputs),
         'Native acceptance retained input records are required')
    for name in ('profile.json', 'lock.json', 'firmware-manifest.json', 'build.config'):
        need(inputs.get(str(raw / name)) == record(raw / name),
             'Native acceptance four RAW metadata records differ: ' + name)
    # Authenticate each retained terminal record, not a copied list of transient
    # attempt IDs. The independent verifier pins actual executions; the explicit
    # approved status SHA binds this complete ordered history and its full refs.
    failures = chain.get('failed_producer_ids')
    failed_processes = chain.get('failed_processes')
    need(isinstance(failed_processes, list) and failed_processes,
         'Native acceptance authenticated failed processes are required')
    seen, failed_codes = set(), {}
    for row in failed_processes:
        need(isinstance(row, dict) and set(row) == {'producer_id', 'process_exit_code', 'inspect'},
             'Native acceptance failed-process fields differ')
        pid, code = row['producer_id'], row['process_exit_code']
        need(isinstance(pid, str) and SHA.fullmatch(pid) and pid not in failed_codes
             and type(code) is int and code > 0, 'Native acceptance failed-process identity/exit differs')
        terminal_path = file_ref(row['inspect'])
        need(str(terminal_path) not in seen and inputs.get(str(terminal_path)) == record(terminal_path),
             'Native acceptance terminal record loses retained input bytes')
        terminal = read(terminal_path, object_only=False)
        if isinstance(terminal, list):
            need(len(terminal) == 1, 'Ambiguous terminal native process inspection')
            terminal = terminal[0]
        need(isinstance(terminal, dict) and terminal.get('Id') == pid,
             'Native acceptance terminal process identity differs')
        state = terminal.get('State', {})
        need(isinstance(state, dict) and state.get('Status') == 'exited' and state.get('Running') is False
             and state.get('OOMKilled') is False and type(state.get('ExitCode')) is int
             and state['ExitCode'] == code, 'Native acceptance terminal process outcome differs')
        failed_codes[pid] = code
        seen.add(str(terminal_path))
    enrolled_failures = [history.get('original_failed_id'), history.get('xxd_resume_failed_id')]
    need(all(isinstance(pid, str) and SHA.fullmatch(pid) for pid in enrolled_failures)
         and len(set(enrolled_failures)) == 2 and isinstance(failures, list)
         and failures == list(failed_codes) and failures[:2] == enrolled_failures
         and chain['final_producer_id'] not in failed_codes,
         'Native acceptance failed projection loses authenticated/enrolled history')
    stages = chain.get('stages', {})
    need(isinstance(stages, dict) and set(stages) == set(STAGES),
         'Native acceptance requires explicit world/IB and final packaging/export stages')
    for name, contract in STAGES.items():
        stage = stages[name]
        need(isinstance(stage, dict)
             and set(stage) == {'producer_id', 'process_exit_code', 'successful_steps', 'manifest', 'runtime_receipts'}
             and isinstance(stage.get('producer_id'), str) and SHA.fullmatch(stage['producer_id'])
             and (failed_codes.get(stage['producer_id']) == 1 if name == 'world_and_imagebuilder'
                  else stage['producer_id'] == chain['final_producer_id'])
             and type(stage.get('process_exit_code')) is int
             and stage['process_exit_code'] == contract['exit_code']
             and stage.get('successful_steps') == contract['steps'],
             'Native acceptance successful steps/process identity differs: ' + name)
        receipts = stage.get('runtime_receipts', {})
        need(isinstance(receipts, dict) and set(receipts) == contract['receipts'],
             'Native acceptance retained stage receipts differ: ' + name)
        manifest_path = file_ref(stage.get('manifest'),
                                 COMPLETION_MANIFEST['sha256'] if name == 'world_and_imagebuilder' else None)
        if name == 'world_and_imagebuilder':
            need(record(manifest_path) == COMPLETION_MANIFEST, 'Native acceptance R3 manifest differs')
            completion = read(manifest_path)
            need(completion.get('kind') == 'native-recommended-selected-ib-completion-v1'
                 and completion.get('attempt_generation') == 'R3'
                 and completion.get('recipe_commit') == PRODUCER and completion.get('source_commit') == SOURCE
                 and completion.get('history', {}).get('original_failed_id') == enrolled_failures[0]
                 and completion['history'].get('xxd_resume_failed_id') == enrolled_failures[1]
                 and failed_codes.get(completion['history'].get('startup_mapping_failed_id')) == 1
                 and completion['history'].get('prior_results_unchanged') is True,
                 'Native acceptance world/IB completion loses retained R2/R3 history')
        # Full refs are supplied by the independently reviewed verifier envelope.
        # Stages may use different runner paths; no imported code is executed.
        for label, item in [('manifest', stage['manifest']), *receipts.items()]:
            retained = file_ref(item)
            need((label == 'manifest' or retained.name == label) and str(retained) not in seen and inputs.get(str(retained)) == record(retained),
                 'Native acceptance stage reference duplicates or loses retained input bytes')
            seen.add(str(retained))
    need(read(raw / 'profile.json') == profile, 'Native acceptance RAW profile differs')
    manifest = read(raw / 'firmware-manifest.json')
    need(manifest.get('recipe_commit') == PRODUCER and manifest.get('source_commit') == SOURCE
         and manifest.get('build_id') == profile['build_id'] and manifest.get('kernel_version') == ABI,
         'Native acceptance RAW producer/generation differs')
    need(set(status.get('native_inputs', {})) == {'profile.json', 'lock.json', 'firmware-manifest.json'}
         and all(record(raw / name) == expected for name, expected in status['native_inputs'].items()),
         'Native acceptance RAW input bytes differ')
    return {'native_acceptance_sha256': pin, **{role + '_sha256': digest for role, digest in APPROVED_REFS.items()},
            'strict_accepted_context_unchanged': True, 'prior_native_image_byte_identical': False,
            'prior_native_abi_context_byte_identical': True, 'accepted_kernel_image': dict(NEW_IMAGE)}
