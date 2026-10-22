"""Small, fail-closed adaptation of the pinned LuCI ASU client for AX6000.

Use apply(profile, source) after feed extraction and before package selection,
for native source and SDK. configure() additionally writes the native overlay.
No running router, service, UCI store or moving upstream source is touched.
"""
from pathlib import Path
import hashlib
import json
import os
import re
import tempfile

REQUIRED_PACKAGES = ('attendedsysupgrade-common', 'luci-app-attendedsysupgrade',
                     'luci-i18n-attendedsysupgrade-ru')
URLS = {'66': 'https://asu.ezon.by/66',
        '612-recommended': 'https://asu.ezon.by/612/recommended',
        '612-latest': 'https://asu.ezon.by/612/latest'}
APP = Path('feeds/luci/applications/luci-app-attendedsysupgrade')
COMMON = Path('feeds/packages/utils/attendedsysupgrade-common')
JS = Path('htdocs/luci-static/resources/view/attendedsysupgrade/overview.js')
ACL = Path('root/usr/share/rpcd/acl.d/luci-app-attendedsysupgrade.json')
STATUS = Path('htdocs/luci-static/resources/view/status/include/11_upgrades.js')
DEFAULTS = Path('files/attendedsysupgrade.defaults')
RELEASE = '2.ax6000asu2'
APP_VERSION = '20261021.2'
APP_APK_RELEASE = '3'
APP_OPKG_RELEASE = '2.ax6000asu3'
COMMON_APK_RELEASE = '2'
PREIMAGES = {
 '66': {'status.js': 'abd71b579331f63933355446648710d93f9ef87a681d2af3a16827c4a2abe47d',
        'overview.js': '0344c89fca79a908cae814e5f7940e24ed191dd82d89ac05d6a8b3cc089c8a13',
        'Makefile': '9d5640151cfccb609f3cbabd15da626c55f39e300fd3a2e7c93977a7214b23c9',
        'common.Makefile': 'b94f1dc69b5dcc7f07b1917d57cba80a5df02818e5e9cc2be2ee8df80a436867'},
 '612': {'status.js': 'b884d19e003e2c4420fb57833a21700d909d367a8e82d26ae49c75a1c4402b4a',
         'overview.js': '3a73818cfdda501d6b597039094297117e64c95e392e0a7340bc808173b47042',
         'Makefile': '571325ec0d68dc25bfdb55d5c5b1cc02292b24f2209d84d7c2b8819dd844e26c',
         'common.Makefile': '98f1cf6f0488d5572de5b623ad56832b999ba1c31f7b8c70253b050fc5cea033'}}
for _row in PREIMAGES.values():
    _row['acl.json'] = 'a9df4afe172faa50d14f87f2a6dc1ec977957d4149c64c52545d7e78d30199ca'
    _row['common.defaults'] = 'dfb1d3fc3a90853c91d8cdea16e757d51aaf59d3208ab8709abbf79b392b0068'


def _require(ok, message):
    if not ok:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def policy(profile):
    spec = profile.get('asu')
    if spec is None:
        return None
    _require(isinstance(spec, dict) and set(spec) == {'enabled', 'cohort', 'server_url', 'seed'} and spec.get('enabled') is True,
             'ASU policy requires enabled:true, cohort, server_url, seed')
    _require(spec.get('cohort') in URLS and spec.get('server_url') == URLS[spec['cohort']],
             'ASU URL must exactly match the firmware cohort (without trailing slash)')
    _require(isinstance(spec.get('seed'), str) and re.fullmatch(r'[0-9a-f]{64}', spec['seed']),
             'ASU seed must be a stable SHA256 generation identity')
    return spec


def package_manager(profile):
    value = profile.get('package_manager', 'opkg')
    _require(value in {'opkg', 'apk'}, 'ASU package manager must be opkg or apk')
    spec = policy(profile)
    _require(spec is None or spec['cohort'] != '66' or value == 'opkg', 'ASU 6.6 requires OPKG')
    _require(spec is None or spec['cohort'] == '66' or value == 'apk',
             'ASU 6.12 new generations require explicit APK package manager')
    return value


def release(profile):
    # APK revision grammar permits a numeric -rN suffix only.
    return APP_APK_RELEASE if package_manager(profile) == 'apk' else APP_OPKG_RELEASE


def common_release(profile):
    return COMMON_APK_RELEASE if package_manager(profile) == 'apk' else RELEASE


def _replace(text, before, after):
    _require(text.count(before) == 1, 'ASU reviewed patch anchor differs')
    return text.replace(before, after, 1)


def patch_overview(data):
    text = _replace(data.decode(), "'require fs';", "'require fs';\n'require ax6000_asu';")
    text = _replace(text, "\tmethod: 'packagelist',\n", "\tmethod: 'packagelist',\n\tparams: ['all'],\n")
    text = _replace(text, 'const callUpgradeStart = rpc.declare({',
        "const callValidateFirmware = rpc.declare({\n\tobject: 'system',\n\tmethod: 'validate_firmware_image',\n\tparams: ['path'],\n});\n\nconst callUpgradeStart = rpc.declare({")
    start = text.index('\tapplyPackageChanges: async function(package_info) {')
    end = text.index('\tselectImage: function ', start)
    text = text[:start] + "\tapplyPackageChanges: async function(package_info) {\n\t\t// No OPKG-to-APK or cross-branch migration for these immutable cohorts.\n\t\treturn package_info.packages;\n\t},\n\n" + text[end:]
    text = _replace(text, '\t\tresponse = response.json();\n\t\tlet image = this.selectImage(response.images, data, firmware);',
        '\t\tresponse = response.json();\n\t\tax6000_asu.target(data.ax6000, response.ax6000);\n\t\tif (!ax6000_asu.same(response.ax6000, data.ax6000Target))\n\t\t\tthrow Error(\'ASU build generation changed during request\');\n\t\tif (response.id !== firmware.profile || response.target !== firmware.target)\n\t\t\tthrow Error(\'ASU build layout or target changed\');\n\t\tlet image = this.selectImage(response.images, data, firmware);')
    text = _replace(text, '\t\t\t\t\t.then((response) => {\n\t\t\t\t\t\tif (response.sha256sum != sha256)',
        "\t\t\t\t\t.then(async (response) => {\n\t\t\t\t\t\tconst validation = await callValidateFirmware('/tmp/firmware.bin');\n\t\t\t\t\t\tconst tested = await fs.exec('/sbin/sysupgrade', ['--test', '/tmp/firmware.bin']);\n\t\t\t\t\t\tif (!validation || validation.valid !== true || tested.code !== 0)\n\t\t\t\t\t\t\tthrow Error('Firmware failed device sysupgrade verification');\n\t\t\t\t\t\tif (response.sha256sum != sha256)")
    text = _replace(text, "\t\t\t\tconst remote_revision = response.json().revision;\n\t\t\t\tif (\n\t\t\t\t\tget_revision_count(revision) < get_revision_count(remote_revision)\n\t\t\t\t) {", "\t\t\t\tconst remote = response.json();\n\t\t\t\tconst remote_revision = remote.revision;\n\t\t\t\tdata.ax6000Target = ax6000_asu.target(data.ax6000, remote.ax6000);\n\t\t\t\tif (ax6000_asu.hasUpgrade(data.ax6000, data.ax6000Target)) {")
    start = text.index('\thandleInstall: function ')
    end = text.index('\thandleCheck: function ', start)
    install = text[start:end]
    install = _replace(install, '\n\t\trequest\n', '\n\t\treturn request\n')
    install = _replace(install, '\n\t\t\t\trequest\n', '\n\t\t\t\treturn request\n')
    install = _replace(install, '\n\t\t\t});\n\t},', "\n\t\t\t}).catch(error => {\n\t\t\t\tui.addNotification(null, E('p', error.message));\n\t\t\t\tui.hideModal();\n\t\t\t});\n\t},")
    text = text[:start] + install + text[end:]
    start = text.index('\thandleCheck: function ')
    end = text.index('\tload: async function ', start)
    check = text[start:end]
    check = _replace(check, '\n\t\tL.resolveDefault(request.get(request_url)).then', '\n\t\treturn L.resolveDefault(request.get(request_url)).then')
    check = _replace(check, '\n\t\t});\n\t},', "\n\t\t}).catch(error => {\n\t\t\tui.addNotification(null, E('p', error.message));\n\t\t\tui.hideModal();\n\t\t});\n\t},")
    text = text[:start] + check + text[end:]
    start = text.index('\thandleRequest: function ')
    end = text.index('\thandleRebuilder: function ', start)
    request = text[start:end]
    request = _replace(request, '\n\t\t\t});\n\t},', "\n\t\t\t}).catch(error => {\n\t\t\t\tpoll.remove(this.pollFn);\n\t\t\t\tui.addNotification(null, E('p', error.message));\n\t\t\t\tui.hideModal();\n\t\t\t});\n\t},")
    text = text[:start] + request + text[end:]
    # These firmware cohorts are snapshots; never expose generic branch migration.
    text = _replace(text, '\t\tlet candidates = [];', "\t\tlet candidates = [];\n\t\tif (!version.endsWith('SNAPSHOT'))\n\t\t\tthrow Error('AX6000 cohort requires a snapshot firmware');")
    text = _replace(text, "\t\t\t\t\to = s.option(form.Value, 'profile', _('Board Name / Profile'));\n", '')
    text = _replace(text, '\t\t\t\t\t\t\t\t\t\t\t\t\tprofile: mapdata.request.profile', '\t\t\t\t\t\t\t\t\t\t\t\t\t...ax6000_asu.request(data.ax6000, data.ax6000Target, data.system_board.board_name,\n\t\t\t\t\t\t\t\t\t\t\t\t\t\tmapdata.request.profile, firmware.packages, packages)')
    text = _replace(text, "\t\t\tuci.load('attendedsysupgrade'),", "\t\t\tuci.load('attendedsysupgrade'),\n\t\t\tfs.read('/etc/asu-cohort.json').then(text => ax6000_asu.identity(JSON.parse(text), false)),\n\t\t\tL.resolveDefault(fs.stat('/lib/apk/db/installed'), null),\n\t\t\tL.resolveDefault(fs.stat('/usr/lib/opkg/status'), null),")
    text = _replace(text, '\t\tconst data = {', '\t\tax6000_asu.runtime(promises[4], promises[5], promises[6]);\n\t\tconst data = {')
    text = _replace(text, '\t\t\tL.resolveDefault(callPackagelist(), {}),', '\t\t\tcallPackagelist(true),')
    text = _replace(text, "\t\t\turl: uci.get_first('attendedsysupgrade', 'server', 'url').replace(/\\/+$/, ''),", "\t\t\turl: ax6000_asu.server(uci.get_first('attendedsysupgrade', 'server', 'url'), promises[4]),\n\t\t\tax6000: promises[4],")
    text = _replace(text, '\t\t\tprofile: promises[1].board_name,', '\t\t\tprofile: ax6000_asu.profile(promises[1].board_name, promises[4]),')
    # No rootfs size override. The immutable matching layout defines flash geometry.
    text = _replace(text, "\t\t\trootfs_size_mb: uci.get('attendedsysupgrade', 'owut', 'rootfs_size'),", '\t\t\trootfs_size_mb: null,')
    return text.encode()


def patch_status(data):
    text = _replace(data.decode(), "'require fs';", "'require fs';\n'require ax6000_asu';")
    # Keep each branch's existing opt-in control and its UCI preference.
    setting = ("'attendedsysupgrade', 'client', 'login_check_for_upgrades'"
               if 'const check_setting =' in text else "'luci', 'main', 'check_for_newer_firmwares'")
    start = text.index('\tload: function() {')
    end = text.index('\n\t},', start) + len('\n\t},')
    text = text[:start] + """\tload: function() {
        return Promise.all([
            callSystemBoard(),
            uci.load('attendedsysupgrade'),
            uci.load('luci'),
            fs.read('/etc/asu-cohort.json').then(text => ax6000_asu.identity(JSON.parse(text), false)),
            L.resolveDefault(fs.stat('/lib/apk/db/installed'), null),
            L.resolveDefault(fs.stat('/usr/lib/opkg/status'), null),
        ]);
    },""" + text[end:]
    start = text.index('\toneshot: function(data) {')
    end = text.index('\n\trender: function(data)', start)
    body = """\toneshot: function(data) {
        if (!uci.get_bool(SETTING))
            return;
        const board = data[0], local = data[3];
        ax6000_asu.runtime(local, data[4], data[5]);
        const url = ax6000_asu.server(uci.get_first('attendedsysupgrade', 'server', 'url'), local);
        ax6000_asu.profile(board.board_name, local);
        return fetch(`${url}/api/v1/revision/${board.release.version}/${board.release.target}`)
            .then(response => { if (!response.ok) throw Error('Upgrade server unavailable'); return response.json(); })
            .then(remote => {
                if (ax6000_asu.hasUpgrade(local, remote.ax6000))
                    ui.addTimeLimitedNotification(_('New Firmware Available'), [
                        E('a', {href: '/cgi-bin/luci/admin/system/attendedsysupgrade'}, _('Attended Sysupgrade')),
                    ], 60000, 'notice');
            })
            .catch(error => console.error('AX6000 upgrade check failed:', error));
    },
""".replace('SETTING', setting)
    return (text[:start] + body + text[end:]).encode()


def _release(data, release_value=RELEASE):
    return _replace(data.decode(), 'include $(TOPDIR)/rules.mk\n',
                    f'include $(TOPDIR)/rules.mk\n\nPKG_RELEASE:={release_value}\n').encode()


def _app_makefile(data, manager='opkg'):
    result = _release(data, APP_APK_RELEASE if manager == 'apk' else APP_OPKG_RELEASE)
    result = _replace(result.decode(), 'PKG_RELEASE:=', 'PKG_VERSION:=' + APP_VERSION + '\nPKG_RELEASE:=').encode()
    if b'LUCI_MINIFY_JS:=' not in result:
        result = _replace(result.decode(), 'LUCI_TITLE:=LuCI support for attended sysupgrades\n',
                          'LUCI_TITLE:=LuCI support for attended sysupgrades\nLUCI_MINIFY_JS:=0\n').encode()
    return result


def _common_makefile(data, manager):
    result = _release(data, COMMON_APK_RELEASE if manager == 'apk' else RELEASE)
    if manager == 'apk':
        # This historical common recipe still installs an OPKG/usign key. APK
        # repository RSA public keys are supplied by the immutable native key
        # overlay, so this unrelated foreign OPKG trust entry is unnecessary.
        result = _replace(result.decode(),
            '\n\t$(INSTALL_DIR) $(1)/etc/opkg/keys/\n\t$(INSTALL_DATA) ./files/ca9d036b25c79698 $(1)/etc/opkg/keys/ca9d036b25c79698\n', '').encode()
    return result


def _acl(data):
    value = json.loads(data)
    read = value['luci-app-attendedsysupgrade']['read']
    read['ubus']['system'].append('validate_firmware_image')
    read['file']['/etc/asu-cohort.json'] = ['read']
    read['file']['/lib/apk/db/installed'] = ['list']
    read['file']['/usr/lib/opkg/status'] = ['list']
    read['ubus']['file'] = ['read', 'stat']
    value['luci-app-attendedsysupgrade']['write']['ubus']['file'] = ['exec']
    # File execution is constrained to the exact standard verification command.
    value['luci-app-attendedsysupgrade']['write']['file'] = {
        '/sbin/sysupgrade --test /tmp/firmware.bin': ['exec']}
    return (json.dumps(value, indent='\t') + '\n').encode()


def _atomic(path, data, mode=0o644):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name, dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data); os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _safe(root, relative):
    path = root / relative
    _require(path.resolve().is_relative_to(root) and not path.is_symlink(), 'ASU path escapes source')
    return path


def _originals(series):
    fixtures = Path(__file__).resolve().parent.parent / 'files/asu-client/upstream' / series
    values = {name: (fixtures / name).read_bytes() for name in PREIMAGES[series]}
    _require({key: digest(value) for key, value in values.items()} == PREIMAGES[series],
             'ASU reviewed original source fixture changed')
    return values


def apply(profile, source, check_only=False):
    spec = policy(profile)
    if spec is None:
        return None
    root = Path(source).resolve(strict=True)
    series = '66' if spec['cohort'] == '66' else '612'
    original = _originals(series)
    module = Path(__file__).resolve().parent.parent / 'files/asu-client/ax6000_asu.js'
    expected = {
        APP / JS: patch_overview(original['overview.js']),
        APP / STATUS: patch_status(original['status.js']),
        APP / 'Makefile': _app_makefile(original['Makefile'], package_manager(profile)),
        APP / ACL: _acl(original['acl.json']),
        APP / 'htdocs/luci-static/resources/ax6000_asu.js': module.read_bytes(),
        COMMON / 'Makefile': _common_makefile(original['common.Makefile'], package_manager(profile)),
        COMMON / DEFAULTS: _replace(original['common.defaults'].decode(),
             'https://sysupgrade.kyarucloud.moe', spec['server_url']).encode()}
    before = {APP / JS: original['overview.js'], APP / STATUS: original['status.js'], APP / 'Makefile': original['Makefile'],
              APP / ACL: original['acl.json'], COMMON / 'Makefile': original['common.Makefile'],
              COMMON / DEFAULTS: original['common.defaults']}
    paths = {relative: _safe(root, relative) for relative in expected}
    pristine = all(path.is_file() and path.read_bytes() == data for relative, data in before.items()
                   for path in [paths[relative]]) and not paths[APP / 'htdocs/luci-static/resources/ax6000_asu.js'].exists()
    applied = all(path.is_file() and path.read_bytes() == expected[relative] for relative, path in paths.items())
    _require(pristine or applied, 'ASU sources differ from complete reviewed preimage/postimage (or partial patch)')
    _require(not check_only or applied, 'ASU client patch is not applied')
    if pristine:
        for relative, data in expected.items():
            _atomic(paths[relative], data)
    return {'cohort': spec['cohort'], 'seed': spec['seed'], 'server_url': spec['server_url'],
            'package_manager': package_manager(profile),
            'release': release(profile), 'changed': pristine,
            'files': {str(path): digest(data) for path, data in expected.items()},
            'required_packages': list(REQUIRED_PACKAGES)}


def configure(profile, source, check_only=False):
    spec = policy(profile)
    if spec is None:
        return None
    root = Path(source).resolve(strict=True)
    identity = {'schema_version': 1, 'cohort': spec['cohort'], 'seed': spec['seed'],
                'package_manager': package_manager(profile)}
    setup = ("#!/bin/sh\n# Bind upgrades to this image's kernel cohort; preserve client preferences.\n"
             "uci -q set attendedsysupgrade.server=server\n"
             f"uci -q set attendedsysupgrade.server.url='{spec['server_url']}'\n"
             "uci -q commit attendedsysupgrade\nexit 0\n").encode()
    files = {'files/etc/asu-cohort.json': (json.dumps(identity, sort_keys=True) + '\n').encode(),
             'files/etc/uci-defaults/99-ax6000-asu': setup}
    paths = {relative: _safe(root, Path(relative)) for relative in files}
    for relative, path in paths.items():
        _require(not path.exists() or (path.is_file() and path.read_bytes() == files[relative]),
                 'ASU native overlay differs from selected cohort policy')
        _require(not check_only or path.is_file(), 'ASU native overlay missing')
    if not check_only:
        for relative, data in files.items():
            _atomic(paths[relative], data, 0o755 if relative.endswith('99-ax6000-asu') else 0o644)
    return {'identity': identity, 'server_url': spec['server_url'],
            'files': {name: digest(data) for name, data in files.items()}}
