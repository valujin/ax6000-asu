"""Fixed hosted callbacks bound privately to the exact reviewed EA inspector.

No recipe globals are patched. No object masquerades as a native source path.
Expected feature content comes from recipe/locked author archives, never the
observed image's optional_features hashes.
"""
import functools
import hashlib
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile
import types


def need(ok, message):
    if not ok:
        raise ValueError(message)


def minified(data, config, tool):
    if not re.search(rb'^CONFIG_LUCI_JSMIN=y$', config, re.M):
        return data
    need(tool is not None and os.access(tool, os.X_OK), 'Explicit trusted hosted jsmin is missing')
    with Path(tool).open('rb') as stream:
        header = stream.read(20)
    need(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00', 'Hosted jsmin must be x86_64 host ELF')
    def limits():
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024**2, 256 * 1024**2))
        resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
        resource.setrlimit(resource.RLIMIT_FSIZE, (8 * 1024**2, 8 * 1024**2))
    with tempfile.TemporaryFile() as output:
        result = subprocess.run([str(tool)], input=data, stdout=output, stderr=subprocess.DEVNULL,
                                timeout=15, preexec_fn=limits)
        need(result.returncode == 0, 'Hosted trusted jsmin failed')
        output.seek(0)
        value = output.read(8 * 1024**2 + 1)
    need(len(value) <= 8 * 1024**2, 'Hosted minified feature exceeds bound')
    return value


def expected_features(hosted, verifier, profile, lock):
    """Same frozen EA rules, with explicit author archives/config/host minifier."""
    module = verifier.image_features
    client, sources, vendor = module.asu_client, module.pbr_sources, module.vendor_country
    files, hashes, versions, suffixes = {}, {}, {}, {}
    policy = client.policy(profile)
    if policy:
        files.update(hosted.expected_overlay())
        # Repository overlay is independently checked by inspect_root as well.
        original = client._originals('612')
        files['www/luci-static/resources/view/attendedsysupgrade/overview.js'] = (client.patch_overview(original['overview.js']), 0o644)
        files['www/luci-static/resources/view/status/include/11_upgrades.js'] = (client.patch_status(original['status.js']), 0o644)
        files['www/luci-static/resources/ax6000_asu.js'] = ((hosted.recipe / 'files/asu-client/ax6000_asu.js').read_bytes(), 0o644)
        files['usr/share/rpcd/acl.d/luci-app-attendedsysupgrade.json'] = (client._acl(original['acl.json']), 0o644)
        files['etc/uci-defaults/50-attendedsysupgrade'] = (original['common.defaults'].replace(b'https://sysupgrade.kyarucloud.moe', policy['server_url'].encode()), 0o644)
        versions['attendedsysupgrade-common'] = '10-r' + client.release(profile)
        versions['luci-app-attendedsysupgrade'] = client.APP_VERSION + '-r' + client.release(profile)
        suffixes['luci-i18n-attendedsysupgrade-ru'] = ''
    if profile.get('vendor_country_db'):
        hashes['usr/share/luci-app-mtwifi-cfg/wireless-mtk.js'] = vendor.POSTIMAGES['612'][0]
        versions['luci-app-mtwifi-cfg'] = '1-r' + (vendor.RELEASES['612'] if hasattr(vendor, 'RELEASES') else vendor.RELEASE)
    pair = sources.validate(profile, lock)
    if pair:
        for name in sources.PACKAGES:
            versions[name] = f"{pair['version']}-r{pair['release']}"
        for language in pair.get('translations', {}):
            versions['luci-i18n-pbr-' + language] = pair['translation_version']
        need(set(hosted.proof.get('pbr_archives', {})) == set(pair['packages']), 'Hosted locked PBR archive roles missing')
        archives = {}
        for name, meta in pair['packages'].items():
            record = hosted.proof['pbr_archives'][name]
            need(record['sha256'] == meta['sha256'], 'Hosted PBR archive differs from author lock')
            path = hosted.checked_record(record, sources.LIMIT)
            archives[name] = sources.read_archive(name, meta, pair, path.read_bytes())
        sources.verify_compatibility(archives)
        selected = ['etc/init.d/pbr', 'etc/config/pbr', 'etc/uci-defaults/90-pbr',
                    'usr/share/pbr/.keep', 'usr/share/pbr/pbr.user.dnsprefetch',
                    'usr/share/pbr/pbr.user.aws.uc', 'usr/share/pbr/pbr.user.netflix.uc']
        selected += ['lib/pbr/' + name + '.uc' for name in
                     ('pbr', 'pkg', 'cli', 'sys', 'validators', 'output', 'config', 'platform', 'network', 'nft')]
        for path in selected:
            need('files/' + path in archives['pbr'], 'Hosted locked PBR file absent: ' + path)
            data = archives['pbr']['files/' + path]
            if path == 'lib/pbr/pkg.uc':
                before = b"\tversion: 'dev-test',"
                need(data.count(before) == 1, 'Hosted PBR version substitution differs')
                data = data.replace(before, ("\tversion: '" + pair['version'] + '-r' + str(pair['release']) + "',").encode(), 1)
            mode = 0o755 if path in ('etc/init.d/pbr', 'etc/uci-defaults/90-pbr') else (0o600 if path == 'etc/config/pbr' else 0o644)
            files[path] = (data, mode)
        config = (hosted.raw / 'build.config').read_bytes()
        for path, data in archives['luci-app-pbr'].items():
            if path.startswith('root/'):
                files[path[5:]] = (data, 0o644)
            elif path.startswith('htdocs/'):
                files['www/' + path[7:]] = (minified(data, config, hosted.tools.get('jsmin')) if path.endswith('.js') else data, 0o644)
    return {'files': files, 'hashes': hashes, 'versions': versions, 'version_suffixes': suffixes}


def verify_features(hosted, verifier, profile, lock, installed, read_file, check_mode, source=None, native_translations=None):
    need(source is None, 'Hosted inspection must not accept a source proxy')
    policy = expected_features(hosted, verifier, profile, lock)
    # A private clone keeps the original feature verification loop verbatim;
    # only its expected-policy dependency is bound to this independent renderer.
    original = verifier.image_features.verify
    namespace = dict(original.__globals__)
    namespace['expected'] = lambda _profile, _lock, _source: policy
    check = types.FunctionType(original.__code__, namespace, original.__name__, original.__defaults__, original.__closure__)
    check.__kwdefaults__ = original.__kwdefaults__
    return check(profile, lock, installed, read_file, check_mode, source=None, native_translations=native_translations)


def apk_policy(hosted, verifier, binary, root, profile, installed, actual_paths, source, apk):
    need(source is None and apk is not None, 'Hosted APK policy requires explicit host decoder and no source proxy')
    need('usr/lib/opkg/status' not in actual_paths and not any(p.startswith('usr/lib/opkg/info/') for p in actual_paths)
         and not {'bin/opkg', 'usr/bin/opkg'} & actual_paths.keys(), 'Hosted APK image retains OPKG state')
    verifier.require_mode(verifier.squash_read(binary, root, 'usr/bin/apk', listing=True), 'usr/bin/apk', 0o755)
    configs = {n for n in actual_paths if n.startswith('etc/apk/repositories.d/') and n.endswith('.list')}
    if 'etc/apk/repositories' in actual_paths:
        configs.add('etc/apk/repositories')
    need({'etc/apk/repositories.d/distfeeds.list', 'etc/apk/repositories.d/customfeeds.list'} <= configs
         and len(configs) <= 16, 'Hosted APK repository inventory differs')
    expected = [row for row in hosted.expected_overlay()['etc/apk/repositories.d/distfeeds.list'][0].splitlines()
                if row and not row.startswith(b'#')]
    active = []
    for name in configs:
        data = verifier.squash_read(binary, root, name, 32 * 1024)
        rows = [row.strip() for row in data.splitlines() if row.strip() and not row.lstrip().startswith(b'#')]
        need(not rows or name == 'etc/apk/repositories.d/distfeeds.list', 'Hosted APK enables an unreviewed repository')
        active.extend(rows)
    need(active == expected, 'Hosted APK public repository origin/tag list differs')
    known = {'etc/apk/keys/immortalwrt-25.12.pem': 'c0da9b5747f3fb16ea64fa37acda4df3723ac22ec30ca0dc6f5c89efc0161f1f',
             'etc/apk/keys/openwrt-25.12.pem': '27d61d827d64ccf2f46dce5f52aec6279404d4a00686dafb22f52f3b4ee675f8'}
    for name, digest in known.items():
        need(hashlib.sha256(verifier.squash_read(binary, root, name, 4096)).hexdigest() == digest, 'Hosted official key differs')
        verifier.require_mode(verifier.squash_read(binary, root, name, listing=True), name, 0o644)
    keys = [name for name in actual_paths if name.startswith('etc/apk/keys/') and name.endswith('.pem')]
    need(3 <= len(keys) <= 16, 'Hosted APK public key inventory differs')
    allowed = set(known.values()) | {profile['apk_key_sha256'], hashlib.sha256(hosted.native_public_key).hexdigest()}
    for name in keys:
        data = verifier.squash_read(binary, root, name, 4096)
        need(hashlib.sha256(data).hexdigest() in allowed and data.startswith(b'-----BEGIN PUBLIC KEY-----\n')
             and data.endswith(b'-----END PUBLIC KEY-----\n'), 'Hosted APK has an unapproved/nonpublic key')
    guard = verifier.apk_world
    records = [{'name': name, 'version': row['Version'], 'depends': row.get('APK-Depends', '').split(),
                'provides': row.get('APK-Provides', '').split(),
                'tags': ['openwrt:abiversion=' + row['ABIVersion']] if row.get('ABIVersion') else []}
               for name, row in installed.items()]
    pins = guard.protected_packages(records, hosted.policy, apk)
    expected_pins = ''.join(name + '=' + version + '\n' for name, version in sorted(pins.items())).encode()
    protected = verifier.squash_read(binary, root, 'etc/apk/ax6000-protected.list', verifier.MIB)
    need(protected == expected_pins, 'Hosted APK protected dependency closure differs')
    world = verifier.squash_read(binary, root, 'etc/apk/world', verifier.MIB).decode('ascii')
    need(world.endswith('\n'), 'Hosted APK world is truncated')
    rows = {}
    for line in world.splitlines():
        token = guard.parse_token(line, world=True)
        need(token[1] not in rows, 'Duplicate hosted APK world constraint')
        rows[token[1]] = token
    for name, version in pins.items():
        need(rows.get(name) == (False, name, None, '=', version), 'Hosted APK native world pin differs')
    return {'package_manager': 'apk', 'public_opt_in_feeds': len(active), 'protected_packages': len(pins),
            'protected_sha256': hashlib.sha256(protected).hexdigest(), 'public_keys': sorted(keys),
            'world_sha256': hashlib.sha256(world.encode()).hexdigest()}


def inspect_hosted_root(verifier, root, layout, binary, profile, controls, archives,
                        expected_overlay, fingerprint, kernel_config, manifest, *, apk, hosted_context):
    hosted = hosted_context
    expected = hosted.recipe / 'scripts/verify-firmware.py'
    need(Path(verifier.__file__).resolve() == expected.resolve()
         and hashlib.sha256(expected.read_bytes()).hexdigest()
         == hosted.data['persisted_ib']['producer_side_source_validation']['code_blobs']['scripts/verify-firmware.py']['sha256'],
         'Hosted inspector is not the exact authenticated EA verifier')
    expected_profile = hosted.profile
    if 'tailscale' in manifest:
        expected_profile = {**hosted.profile, 'package_only':
                            [name for name in hosted.profile.get('package_only', []) if name != 'tailscale']}
    need(getattr(hosted, 'tree_verified', False) and layout in {'stock', 'mtkuboot', 'ubootmod'}
         and profile == expected_profile,
         'Hosted root inspection identity differs')
    hosted.validate_inspector_dependencies(verifier)
    original = verifier.inspect_root
    need(Path(original.__code__.co_filename).resolve() == expected.resolve(),
         'Hosted inspector code was replaced')
    namespace = dict(original.__globals__)
    namespace['apk_root_policy'] = functools.partial(apk_policy, hosted, verifier)
    namespace['image_features'] = types.SimpleNamespace(verify=functools.partial(verify_features, hosted, verifier))
    inspect = types.FunctionType(original.__code__, namespace, original.__name__, original.__defaults__, original.__closure__)
    inspect.__kwdefaults__ = original.__kwdefaults__
    result = inspect(root, layout, binary, profile, controls, archives, expected_overlay, fingerprint,
                     kernel_config, manifest, feature_lock=hosted.lock, feature_source=None, apk=apk)
    result['hosted_context'] = {**hosted.scope, 'callback_source_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                                'inspector_source_sha256': hashlib.sha256(expected.read_bytes()).hexdigest()}
    return result
