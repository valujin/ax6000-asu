#!/usr/bin/env python3
"""Offline operator promotion of verified native artifacts and signed snapshots.

No engine, network, package scripts, target binaries or private keys are used.
Independent native/smoke/loaded-image receipt digests are explicit trust inputs;
signatures, package banks and every referenced local artifact are checked again.
"""
import argparse
import base64
from contextlib import contextmanager
import ctypes
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SHA = re.compile(r'[a-f0-9]{64}')
NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.+-]{0,127}')
MAX_JSON = 32 * 1024**2
MAX_CATALOG = 8 * 1024**2
CORE = {'kernel','libc','base-files','busybox','libgcc','libstdcpp','libatomic',
        'procd','procd-seccomp','procd-ujail','ubox','ubus','netifd','fstools',
        'usign','openwrt-keyring','logd','mtd','firewall4','urngd'}
ASU = {'attendedsysupgrade-common','luci-app-attendedsysupgrade','luci-i18n-attendedsysupgrade-ru'}
VENDOR = {'kmod-mt_wifi','kmod-mediatek_hnat','kmod-conninfra','kmod-warp','mtwifi-cfg-ucode',
          'luci-app-mtwifi-cfg','iwinfo-ucode','ucode-mod-iwinfo','ucode-mod-datconf',
          'ucode-mod-l1parser','wifi-dats','libiwinfo'}
LAYOUTS = {'stock','mtkuboot','ubootmod'}
PUBLIC_TAG = 'public'
OPERATOR_PUBLISHER = {
    'publish.py': (26070, '977e0eefa6acdc3eeb178b36de0ba719a0f8afe27576152dbb74a759c4988105'),
    'package_format.py': (14099, '0ab7b8e010b3f81a64fb325ce3773f58a82f2195c29a1b4de7edb6d47eff0744'),
}


def require(ok, message):
    if not ok: raise ValueError(message)


def sha256(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def canonical(data):
    return (json.dumps(data, sort_keys=True, indent=2, allow_nan=False)+'\n').encode()


def catalog_bytes(data):
    payload=(json.dumps(data,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
    require(len(payload)<=MAX_CATALOG,'Complete candidate catalog exceeds the 8 MiB policy bound')
    return payload


def regular(path, cap=MAX_JSON):
    path=Path(path).absolute()
    require(path.is_file() and not any(p.is_symlink() for p in (path,*path.parents))
            and path.stat().st_size<=cap, 'Missing, linked or oversized input: '+str(path))
    return path


def read_json(path, pin=None):
    path=regular(path)
    payload=path.read_bytes()
    if pin is not None:
        require(isinstance(pin,str) and SHA.fullmatch(pin) and hashlib.sha256(payload).hexdigest()==pin, 'Independent receipt SHA256 differs')
    def unique(pairs):
        result={}
        for key,value in pairs:
            require(key not in result,'Duplicate JSON field');result[key]=value
        return result
    def constant(_): raise ValueError('Nonfinite JSON value')
    data=json.loads(payload,object_pairs_hook=unique,parse_constant=constant)
    require(isinstance(data,dict),'Expected a JSON object')
    return data


def load_module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);sys.modules[name]=module
    spec.loader.exec_module(module)
    return module


@contextmanager
def recipe_modules(repository, commit):
    repository=Path(repository).absolute()
    require(re.fullmatch(r'[a-f0-9]{40}',commit or ''),'An approved recipe commit is required')
    actual=subprocess.check_output(['git','-C',str(repository),'rev-parse','HEAD'],text=True).strip()
    require(actual==commit,'Trusted package recipe HEAD differs from approved commit')
    changes=subprocess.check_output(['git','-C',str(repository),'status','--porcelain','--untracked-files=all','--','scripts','keys','profiles','files'])
    require(not changes,'Trusted package recipe scripts/keys/profiles/files must match their committed bytes')
    old=list(sys.path);sys.path.insert(0,str(repository/'scripts'))
    names=('publish','prepare','package_format','firmware_layouts','imagebuilder','fit_payload','stock_factory')
    saved={name:sys.modules.pop(name) for name in names if name in sys.modules}
    try:
        yield repository
    finally:
        for name in names:sys.modules.pop(name,None)
        sys.modules.update(saved);sys.path[:]=old


def pinned_tool(path,pin):
    path=regular(path,64*1024**2)
    require(SHA.fullmatch(pin or '') and sha256(path)==pin and os.access(path,os.X_OK),
            'Trusted host tool checksum/executable differs')
    return path


def reviewed_operator_publisher(directory,cohort):
    """One literal operator source closure, separate from the native recipe."""
    require(cohort in {'612-recommended','612-latest'},'Operator publisher is only for APK cohorts')
    directory=Path(directory).absolute()
    require(directory.is_dir() and not any(p.is_symlink() for p in (directory,*directory.parents)),
            'Operator publisher directory is missing or linked')
    require({p.name for p in directory.iterdir()}==set(OPERATOR_PUBLISHER),
            'Operator publisher closure has an unexpected or missing sibling')
    records={}
    for name,(size,pin) in OPERATOR_PUBLISHER.items():
        path=regular(directory/name,size)
        require(path.stat().st_size==size and sha256(path)==pin,'Operator publisher source checksum differs')
        records[name]={'path':str(path),'size':size,'sha256':pin}
    # Both fixed files are loaded now, without creating an unapproved sibling.
    # The publisher caches its format module, so subsequent validation needs no
    # bytecode write and the caller's interpreter setting is restored.
    previous=sys.dont_write_bytecode;sys.dont_write_bytecode=True
    try:
        publisher=load_module(directory/'publish.py','promote_operator_publisher')
        publisher.package_format()
    finally:sys.dont_write_bytecode=previous
    publisher.asu_operator_publisher_scope={'role':'reviewed-operator-publisher',
        'native_producer_replaced':False,'files':records}
    return publisher


def inventory(tree,exclude=()):
    tree=Path(tree);result=[];total=0
    require(tree.is_dir() and not tree.is_symlink(),'Expected a regular snapshot tree')
    for path in sorted(tree.rglob('*')):
        require(not path.is_symlink() and (path.is_file() or path.is_dir()),'Snapshot links and special files are forbidden')
        if path.is_dir():continue
        name=path.relative_to(tree).as_posix()
        if name in exclude:continue
        total+=path.stat().st_size
        require(total<=1024**3 and len(result)<100000,'Snapshot exceeds publication bounds')
        result.append({'path':name,'size':path.stat().st_size,'sha256':sha256(path)})
    return result


def snapshot_identity(snapshot,cohort,public_key,usign,recipe,apk=None,*,operator_publisher_dir=None):
    snapshot=Path(snapshot)
    channel=snapshot/'channel' if (snapshot/'channel').is_dir() else snapshot
    manifest=snapshot/'snapshot-manifest.json';signature=snapshot/'snapshot-manifest.sig'
    publisher=(reviewed_operator_publisher(operator_publisher_dir,cohort) if operator_publisher_dir is not None
               else load_module(recipe/'scripts/publish.py','promote_publisher'))
    subprocess.run([str(usign),'-V','-m',str(regular(manifest)),'-p',str(public_key),'-x',str(regular(signature))],
                   check=True,capture_output=True,timeout=30)
    proof=read_json(manifest);profile=read_json(channel/'profile.json')
    require(proof.get('schema_version')==1 and proof.get('profile_id')==profile.get('id')
            and proof.get('build_id')==profile.get('build_id')
            and proof.get('kernel_version')==profile['firmware']['kernel_version'],'Signed snapshot generation differs')
    excluded={'snapshot-manifest.json','snapshot-manifest.sig'} if channel==snapshot else set()
    files=inventory(channel,excluded)
    require(proof.get('files')==files,'Signed snapshot inventory differs from actual tree')
    lock=read_json(channel/'state/lock.json')
    require(lock.get('profile_sha256')==sha256(channel/'profile.json')
            and lock.get('firmware')==profile['firmware'] and lock.get('sdk')==profile['sdk'],'Snapshot profile/lock differs')
    require(publisher.public_key_payload((channel/'repository.pub').read_text())==publisher.public_key_payload(Path(public_key).read_text()),
            'Snapshot repository key differs from trusted key')
    if cohort=='66':
        require(proof.get('cohort')=='66' and profile.get('package_manager','opkg')=='opkg'
                and profile.get('channel') is None,'Wrong OPKG snapshot cohort')
        # The OPKG publisher uses the same bounded control/index format. Its
        # immutable envelope has no 6.12 channel/release pointer fields.
        feed=channel/'feeds'/profile['id']/profile['firmware']['kernel_version']
        verify_opkg_feed(feed,profile,public_key,usign,publisher)
    else:
        require(profile.get('channel')==cohort.removeprefix('612-') and profile.get('package_manager')=='apk','Wrong APK snapshot cohort')
        validator=load_module(recipe/'scripts/channel-snapshot.py','promote_snapshot')
        if operator_publisher_dir is not None:
            # This fresh module alone uses the reviewed publisher. Every other
            # helper still comes from the original, committed native recipe.
            original_module=validator.module
            validator.module=lambda name: publisher if name=='publish' else original_module(name)
        validator.validate_channel(channel,profile['channel'],profile['publication']['repository'],public_key,usign,apk=apk)
    return profile,channel,sha256(manifest),files,publisher


def verify_opkg_feed(feed,profile,public_key,usign,publisher):
    import gzip
    index=regular(feed/'Packages',8*1024**2)
    subprocess.run([str(usign),'-V','-m',str(index),'-p',str(public_key),'-x',str(regular(feed/'Packages.sig'))],
                   check=True,capture_output=True,timeout=30)
    with gzip.open(regular(feed/'Packages.gz'),'rb') as stream:expanded=stream.read(8*1024**2+1)
    require(expanded==index.read_bytes(),'Compressed package index differs')
    names=set();filenames=set()
    for paragraph in index.read_text().strip().split('\n\n'):
        fields={};last=None
        for line in paragraph.splitlines():
            if line.startswith((' ','\t')) and last:fields[last]+='\n'+line
            else:
                require(':' in line,'Malformed signed index')
                key,value=line.split(':',1);require(key not in fields,'Duplicate package index field')
                fields[key]=value.strip();last=key
        filename=fields.get('Filename','')
        require(re.fullmatch(r'[A-Za-z0-9_.+~-]+\.ipk',filename) and filename not in filenames,'Unsafe or duplicate package filename')
        path=regular(feed/filename,256*1024**2)
        require(str(path.stat().st_size)==fields.get('Size') and sha256(path)==fields.get('SHA256sum'),'Signed package archive differs')
        control=publisher.read_control(path);publisher.validate_package(control,profile)
        require(all(fields.get(k)==v for k,v in control.items()),'Signed package control differs')
        require(control['Package'] not in names and control['Package'] not in {'kernel','libc','base-files','busybox','opkg'},'Protected or duplicate supplemental package')
        names.add(control['Package']);filenames.add(filename)
    require(filenames and filenames=={p.name for p in feed.glob('*.ipk')},'Incomplete OPKG package inventory')


def package_identity(control):
    name=control['Package'];abi=control.get('ABIVersion','')
    require(isinstance(abi,str) and (not abi or (name.endswith(abi) and len(name)>len(abi))),
            'Declared native ABI suffix differs from actual package name')
    base=control.get('Base-Package',name[:-len(abi)] if abi else name)
    require(NAME.fullmatch(base) and name==base+abi,'Ambiguous native package ABI identity')
    return base,{'name':name,'abi':abi,'version':control['Version'],'tag':''}


def identities(bank):
    result={};controls={}
    for item in bank:
        control=item['control'];base,identity=package_identity(control)
        require(base not in result,'Ambiguous native package ABI identity')
        result[base]=identity
        controls[base]=control
    return result,controls


def provided_names(control):
    base,identity=package_identity(control)
    return {base,identity['name']}|set(re.findall(r'(?:^|,)\s*([A-Za-z0-9_.+:-]+)',control.get('Provides','')))


def parse_manifest(path,identity):
    reverse={item['name']:base for base,item in identity.items()};result={}
    for line in regular(path,8*1024**2).read_text().splitlines():
        if not line.strip():continue
        fields=line.split(' - ')
        require(len(fields)==2,'Malformed actual image package manifest')
        name=reverse.get(fields[0],fields[0]);version=fields[1]
        require(name in identity and name not in result and identity[name]['version']==version,'Image manifest package/version differs from approved bank')
        result[name]=version
    require(result,'Empty actual image package manifest')
    return result


def artifact(directory,record,cap=128*1024**2):
    require(isinstance(record,dict),'Missing smoke artifact identity')
    name=record.get('path','');relative=PurePosixPath(name)
    require(isinstance(name,str) and name and str(relative)==name and not relative.is_absolute() and '..' not in relative.parts,'Unsafe receipt artifact path')
    path=regular(Path(directory)/name,cap)
    require(record.get('size')==path.stat().st_size and record.get('sha256')==sha256(path),'Receipt artifact bytes differ: '+name)
    return path


def native_layouts(evidence,raw,profile,identity,cohort):
    require(evidence.get('schema_version')==1 and evidence.get('ok') is True
            and evidence.get('build_id')==profile['build_id'] and evidence.get('source_commit')==profile['firmware']['commit']
            and evidence.get('kernel_abi')==profile['firmware']['kernel_version'],'Native verification receipt identity differs')
    require(evidence.get('sdk_context',{}).get('sdk_sha256')==profile['sdk']['sha256'],
            'Native SDK context differs from signed generation')
    layouts=evidence.get('layouts',{});required={'stock'} if cohort=='66' else LAYOUTS
    require(set(layouts)==required,'Native evidence layout coverage differs')
    target=Path(raw)/'bin/targets/mediatek/filogic';installed={};versions=set()
    for layout,record in layouts.items():
        image=regular(target/record['image'],128*1024**2)
        require(image.name==record['image'] and sha256(image)==record['image_sha256'] and image.stat().st_size==record['image_size'],'Native image bytes differ from receipt')
        root=record['root'];manifest=regular(target/root['package_manifest']['filename'])
        require(root['package_manifest']['filename']==manifest.name,'Native manifest path must be a single target filename')
        require(sha256(manifest)==root['package_manifest']['sha256'],'Native installed manifest bytes differ')
        packages=parse_manifest(manifest,identity)
        reverse={item['name']:name for name,item in identity.items()}
        require(set(packages)=={reverse.get(name,name) for name in root['installed_packages']},'Native installed package inventory differs')
        require('tailscale' not in packages,'Native defaults unexpectedly include Tailscale')
        require(packages.get('kernel')==profile['firmware']['kernel_version']
                and record['kernel']['sha256']==evidence.get('sysupgrade_input',{}).get('sha256'),
                'Native installed kernel or actual Image input differs')
        installed[layout]=packages
        metadata=record['metadata'];supported=metadata.get('new_supported_devices',metadata.get('supported_devices'))
        device='xiaomi_redmi-router-ax6000-'+layout
        require(supported==[device.replace('xiaomi_','xiaomi,')],'Native supported layout differs')
        version=metadata['version'];require(version.get('target')=='mediatek/filogic' and version.get('board')==device,'Native image metadata target differs')
        versions.add((version.get('version'),version.get('revision')))
    require(len(versions)==1,'Native firmware version differs across layouts')
    return installed,next(iter(versions))


def dependency_closure(roots,installed,controls):
    providers={}
    for name in installed:
        control=controls[name]
        for provided in [control['Package'],name]+re.findall(r'(?:^|,)\s*([A-Za-z0-9_.+:-]+)',control.get('Provides','')):
            providers.setdefault(provided,set()).add(name)
    pending=set(roots);closure=set()
    while pending:
        name=pending.pop()
        require(name in installed,'Required native policy package is not installed: '+name)
        if name in closure:continue
        closure.add(name)
        for group in controls[name].get('Depends','').split(','):
            if not group.strip() or group.strip().startswith('!'):continue
            alternatives=re.findall(r'(?:^|\|)\s*([A-Za-z0-9_.+:-]+)',group)
            candidates=set().union(*(providers.get(x,set()) for x in alternatives))
            require(candidates,'Native protected dependency is unavailable: '+name+': '+group)
            pending.update(candidates-closure)
    return closure


def core_roots(tree):
    roots=set();recipe=''
    for line in regular(Path(tree)/'.packageinfo',32*1024**2).read_text().splitlines():
        if line.startswith('Source-Makefile:'):recipe=line.split(':',1)[1].strip()
        elif line.startswith('Package:') and recipe.startswith('package/') and not recipe.startswith(('package/feeds/','package/ax6000-overrides/')):
            roots.add(line.split(':',1)[1].strip())
    require(roots,'Missing actual native core package recipe policy')
    return roots


def overlay_records(source,profile,native,fingerprint):
    """Collect only the known source overlay, bound across every inspected image."""
    paths={'etc/asu-cohort.json':0o644,'etc/uci-defaults/99-ax6000-asu':0o755,
           'usr/sbin/ax6000-install-feed':0o755}
    if profile.get('package_manager','opkg')=='apk':
        paths.update({name:0o644 for name in ('etc/apk/repositories.d/distfeeds.list',
            'etc/apk/repositories.d/customfeeds.list','etc/apk/keys/repository-apk.pem','etc/ax6000/repository.pub')})
    else:
        require(re.fullmatch(r'[a-f0-9]{16}',fingerprint),'Invalid production OPKG key fingerprint')
        paths.update({'etc/opkg/distfeeds.conf':0o644,'etc/opkg/keys/'+fingerprint:0o644})
    result={};total=0
    require(isinstance(native.get('layouts'),dict) and native['layouts'],'Missing native overlay inspection')
    for name,mode in paths.items():
        path=regular(Path(source)/'files'/name,64*1024)
        content=path.read_bytes();digest=hashlib.sha256(content).hexdigest();total+=len(content)
        require(path.stat().st_mode&0o7777==mode and total<=1024**2,'Native overlay mode or total size differs')
        for layout,evidence in native['layouts'].items():
            root=evidence.get('root',{})
            repository=root.get('repository_files',{})
            feature=(root.get('optional_features') or {}).get('files',{})
            records=[record for record in (repository.get(name),feature.get(name)) if record is not None]
            require(records,'Native '+layout+' proof does not inspect overlay path: '+name)
            for record in records:
                actual_mode=record.get('mode')
                if isinstance(actual_mode,str) and re.fullmatch(r'0[0-7]{3}',actual_mode):actual_mode=int(actual_mode,8)
                require(record.get('sha256')==digest and actual_mode==mode
                        and ('size' not in record or record['size']==len(content)),
                        'Actual native '+layout+' overlay bytes/mode differ: '+name)
        result[name]={'content_base64':base64.b64encode(content).decode('ascii'),'sha256':digest,'mode':mode}
    return result


def rootfs_overlay(recipe,source,profile,native,attestation):
    """Render-check committed recipe bytes before collecting actual source files.

    Build-time APK world helpers stay in the independently verified IB context.
    Their per-image protected list must be regenerated, never copied from native.
    """
    renderer=load_module(Path(recipe)/'scripts/prepare-firmware.py','promote_overlay_renderer')
    if profile.get('package_manager','opkg')=='apk':
        renderer.repository_files(Path(source),check_only=True,profile=profile)
        guard=load_module(Path(recipe)/'scripts/apk_world.py','promote_overlay_apk_guard')
        guard.configure_source(profile,Path(source),check_only=True)
        guard.configure_policy(profile,Path(source),check_only=True)
        required={'ax6000-apk-world-policy.json','scripts/ax6000-apk-world.py','include/rootfs.mk'}
        require(required<={item['path'] for item in attestation['context']},'ImageBuilder omits dynamic APK world guard context')
        for evidence in native.get('layouts',{}).values():
            policy=evidence.get('root',{}).get('apk_policy') or {}
            require(policy.get('package_manager')=='apk' and type(policy.get('protected_packages')) is int
                    and policy['protected_packages']>0 and SHA.fullmatch(policy.get('protected_sha256',''))
                    and SHA.fullmatch(policy.get('world_sha256','')),'Native evidence has no verified dynamic APK world protection')
    else:
        renderer.repository_files(Path(source),check_only=True)
    client=load_module(Path(recipe)/'scripts/asu_client.py','promote_overlay_asu')
    client.configure(profile,Path(source),check_only=True)
    publisher=load_module(Path(recipe)/'scripts/publish.py','promote_overlay_publisher')
    payload=publisher.public_key_payload((Path(recipe)/'keys/repository.pub').read_text())
    return overlay_records(source,profile,native,payload[2:10].hex())


def apk_protected_roots(source,attestation):
    """Read canonical roots from the exact source policy attested in the IB.

    Call only after rootfs_overlay has read-only checked configure_policy. These
    roots differ from ASU mandatory packages; installed roots select the native
    guard's minimum pins and the hook computes its actual dependency closure.
    """
    path=regular(Path(source)/'ax6000-apk-world-policy.json')
    records=[record for record in attestation.get('context',[]) if record.get('path')=='ax6000-apk-world-policy.json']
    require(len(records)==1 and records[0].get('sha256')==sha256(path)
            and records[0].get('size')==path.stat().st_size,'APK protected roots differ from attested native policy')
    policy=read_json(path);roots=policy.get('protected_roots')
    require(policy.get('schema_version')==1 and policy.get('package_manager')=='apk'
            and isinstance(roots,list) and roots and len(roots)<=10000
            and all(isinstance(name,str) and NAME.fullmatch(name) for name in roots)
            and roots==sorted(set(roots)),'Invalid attested canonical APK protected roots')
    return roots


def smoke_evidence(evidence,directory,profile,attestation_sha,snapshot_sha,native,installed,identity):
    expected={'build_id':profile['build_id'],'source_commit':profile['firmware']['commit'],
              'kernel_version':profile['firmware']['kernel_version'],'architecture':profile['firmware']['architecture'],
              'target':'mediatek/filogic'}
    if profile.get('package_manager')=='apk':expected['package_manager']='apk'
    require(evidence.get('schema_version')==1 and evidence.get('kind')=='ax6000-imagebuilder-smoke'
            and evidence.get('identity')==expected and evidence.get('archive_sha256')==profile['imagebuilder']['sha256']
            and evidence.get('attestation_sha256')==attestation_sha and evidence.get('snapshot_sha256')==snapshot_sha,
            'ImageBuilder smoke receipt archive/generation/snapshot identity differs')
    require(set(evidence.get('layouts',{}))==set(native),'ImageBuilder smoke does not cover actual layouts')
    for layout,record in evidence['layouts'].items():
        require(record.get('exit_codes')=={'info':0,'manifest':0,'image':0},'ImageBuilder real make command did not succeed')
        info=artifact(directory,record.get('info'),8*1024**2)
        require(('xiaomi_redmi-router-ax6000-'+layout) in info.read_text(),'Actual make info omits requested layout')
        emitted=parse_manifest(artifact(directory,record.get('manifest'),8*1024**2),identity)
        require('tailscale' not in emitted and set(installed[layout])<=set(emitted),'Default smoke dropped installed packages or included Tailscale')
        artifact(directory,record.get('image'))
        metadata=read_json(artifact(directory,record.get('metadata'),1024**2))
        device='xiaomi_redmi-router-ax6000-'+layout
        require(metadata.get('new_supported_devices',metadata.get('supported_devices'))==[device.replace('xiaomi_','xiaomi,')]
                and metadata.get('version',{}).get('board')==device
                and metadata['version'].get('target')=='mediatek/filogic','Smoke image metadata targets a foreign layout')
        require(record.get('kernel_sha256')==native[layout]['kernel']['sha256'],'Smoke kernel bytes differ from verified native image')


def rename_new(source,destination):
    """Linux atomic directory install with RENAME_NOREPLACE; never replace state."""
    libc=ctypes.CDLL(None,use_errno=True)
    result=libc.renameat2(-100,os.fsencode(source),-100,os.fsencode(destination),1)
    if result!=0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error),str(destination))


def write_new(path,data):
    with Path(path).open('xb') as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    Path(path).chmod(0o444)


def copy_new(source,target):
    with Path(source).open('rb') as src,Path(target).open('xb') as dst:
        shutil.copyfileobj(src,dst,1024**2);dst.flush();os.fsync(dst.fileno())
    Path(target).chmod(0o444)


def immutable_copy(channel,manifest_root,files,store,snapshot_sha):
    store=Path(store).absolute()
    require(not any(p.is_symlink() for p in (store,*store.parents)),'Immutable store has linked components')
    store.mkdir(parents=True,exist_ok=True);parent=store/'immutable';parent.mkdir(exist_ok=True)
    destination=parent/snapshot_sha
    require(not destination.exists(),'Immutable snapshot destination already exists')
    with tempfile.TemporaryDirectory(prefix='.promote-',dir=parent) as temporary:
        stage=Path(temporary);(stage/'channel').mkdir()
        for record in files:
            source=regular(Path(channel)/record['path'],1024**3)
            require(sha256(source)==record['sha256'] and source.stat().st_size==record['size'],'Snapshot changed during immutable copy')
            target=stage/'channel'/record['path'];target.parent.mkdir(parents=True,exist_ok=True)
            copy_new(source,target)
            require(sha256(target)==record['sha256'] and target.stat().st_size==record['size'],'Snapshot changed while copying')
        for name in ('snapshot-manifest.json','snapshot-manifest.sig'):
            write_new(stage/name,regular(Path(manifest_root)/name).read_bytes())
        require(sha256(stage/'snapshot-manifest.json')==snapshot_sha,'Snapshot manifest changed during copy')
        for directory in sorted((p for p in stage.rglob('*') if p.is_dir()),reverse=True):directory.chmod(0o555)
        stage.chmod(0o555);rename_new(stage,destination)
    return destination


def public_candidates(registry_path,registry_sha,snapshot_sha,identity,controls,protected,
                      apk,apk_sha,site,mirror_root=None,mirror_prefix='/indexes'):
    """Verify frozen indexes and collect candidates; mutually exclusive apps coexist."""
    mirror=load_module(ROOT/'ops/immutable_mirror.py','promote_mirror')
    registry=read_json(registry_path,registry_sha)
    require(registry.get('schema_version')==1,'Wrong mirror registry schema')
    snapshots=[s for s in registry.get('snapshots',[]) if s.get('snapshot_sha256')==snapshot_sha]
    require(len(snapshots)==1,'Mirror registry does not name this exact signed snapshot')
    decoder=mirror.Decoder(apk,apk_sha);repositories=[];candidates={};owners={};ambiguous=set();feeds=set();distribution=None
    native_names=set(identity)|{item['name'] for item in identity.values()}
    for control in controls.values():native_names.update(provided_names(control))
    fmt=sys.modules.get('package_format')
    require(fmt is not None,'Trusted APK format decoder was not loaded')
    definitions=snapshots[0].get('repositories',[])
    require(isinstance(definitions,list) and 0<len(definitions)<=6,'Select at most the six approved userspace feeds')
    for original in definitions:
        record=dict(original)
        if mirror_root is not None:
            prefix=PurePosixPath(mirror_prefix)
            require(prefix.is_absolute() and str(prefix)==mirror_prefix and mirror_prefix!='/' and '..' not in prefix.parts,'Unsafe container index prefix')
            for field in ('index_path','key_path'):
                path=PurePosixPath(record.get(field,''))
                require(path.is_absolute() and path.is_relative_to(prefix) and '..' not in path.parts and str(path)==record[field],
                        'Mirror registry path is outside its container index prefix')
                record[field]=str(Path(mirror_root).absolute()/path.relative_to(prefix))
        require(record.get('distribution') in {'immortalwrt','openwrt'},'Public policy requires ImmortalWrt or OpenWrt 25.12')
        if distribution is None:distribution=record['distribution']
        require(record['distribution']==distribution,'A frozen snapshot cannot mix public distributions')
        repo=mirror.Repository(record,decoder);repositories.append((record,repo))
        require(repo.feed not in feeds,'Duplicate frozen public feed');feeds.add(repo.feed)
        for filename,raw in repo.rows.items():
            control=fmt.normalize_apk_info(raw);base=control['Base-Package'];name=control['Package']
            if not NAME.fullmatch(base) or not NAME.fullmatch(name):continue
            if base in native_names or base in CORE|ASU|VENDOR or base.startswith(('kmod-','apk')) or base=='opkg':continue
            if name in native_names:continue
            aliases=re.findall(r'(?:^|,)\s*([A-Za-z0-9_.+:-]+)',control.get('Provides',''))
            if any(alias.removesuffix('-any') in protected or alias in native_names for alias in aliases):continue
            if re.search(r'(?:^|,)\s*(?:kernel(?:\s|\(|,|$)|kmod-)',control.get('Depends','')):continue
            if base in candidates:
                ambiguous.add(base)
                continue
            candidates[base]=control;owners[name]=(record,repo,filename)
    for base in ambiguous:candidates.pop(base,None)
    origins={};indexes={};urls=[];keytexts=[]
    for record,repo in repositories:
        url=site+'/immutable/'+snapshot_sha+'/public/'+repo.sha+'/'+repo.feed+'/packages.adb'
        indexes['public-'+repo.feed]={'url':url,'sha256':repo.sha}
        urls.append('@'+PUBLIC_TAG+' '+url);keytexts.append(regular(record['key_path'],16384).read_text())
    for base,control in candidates.items():
        record,repo,filename=owners[control['Package']]
        origins[base]={'repository':'public-'+repo.feed,'filename':filename,'identity_sha256':repo.rows[filename]['hashes']}
    return {'controls':candidates,'owners':owners,'repositories':repositories,
            'origins':origins,'indexes':indexes,'urls':urls,'keys':keytexts,'distribution':distribution}


def solve_public(catalog,selected,identity,protected,tree,feed,apk,public_key):
    """Validate only requested roots together; never solve the complete inventory."""
    require(selected and len(selected)<=128,'Select one to 128 public userspace roots explicitly')
    candidates=catalog['controls'];owners=catalog['owners'];repositories=catalog['repositories']
    require(all(name in candidates for name in selected),'Public selection collides, is protected, ambiguous, or is unavailable')
    public_by_actual={control['Package']:control for control in candidates.values()}
    with tempfile.TemporaryDirectory(prefix='asu-promote-solver-') as temporary:
        work=Path(temporary);keys=work/'keys';keys.mkdir();root=work/'root'
        for directory in ('lib/apk/db','etc/apk'): (root/directory).mkdir(parents=True,exist_ok=True)
        for name in ('lib/apk/db/installed','etc/apk/world'): (root/name).touch()
        (root/'etc/apk/arch').write_text('aarch64_cortex-a53\n')
        for index,key in enumerate([*(tree/'keys').glob('*'),public_key,*[Path(r['key_path']) for r,_ in repositories]]):
            (keys/(str(index)+'.pem')).write_bytes(regular(key,16384).read_bytes())
        native=(tree/'packages/packages.adb').resolve();supplement=(feed/'packages.adb').resolve()
        lines=[native.as_uri(),supplement.as_uri()]
        lines += ['@'+PUBLIC_TAG+' '+Path(record['index_path']).resolve().as_uri() for record,_ in repositories]
        repos=work/'repositories';repos.write_text('\n'.join(lines)+'\n')
        pins=[identity[name]['name']+'='+identity[name]['version'] for name in sorted(protected)]
        requests=[candidates[name]['Package']+'@'+PUBLIC_TAG+'='+candidates[name]['Version'] for name in selected]
        command=[str(apk),'--root',str(root),'--arch','aarch64_cortex-a53','--no-network',
                 '--keys-dir',str(keys),'--repositories-file',str(repos),'--no-cache']
        # query.c deliberately ignores conflicts. A real simulated transaction
        # must succeed before using query's structured closure/origin output.
        simulated=subprocess.run([*command,'--no-scripts','--no-commit-hooks','--usermode',
                                  'add','--simulate',*pins,*requests],capture_output=True,timeout=120)
        require(simulated.returncode==0 and not simulated.stderr.strip(),'Native public dependency solver simulation failed')
        command += ['query','--from','repositories',
                 '--recursive','--format','json','--fields','name,version,arch,depends,repositories,download-url',*pins,*requests]
        result=subprocess.run(command,check=True,capture_output=True,timeout=120)
        require(not result.stderr.strip() and len(result.stdout)<=32*1024**2,'Native public dependency solver reported an error')
        rows=json.loads(result.stdout);require(isinstance(rows,list) and rows,'Empty native solver closure')
        actual_to_base={item['name']:base for base,item in identity.items()}
        selected_controls={};native_names=set();seen=set()
        for row in rows:
            name=row.get('name');version=row.get('version');require(name not in seen,'Duplicate solver package');seen.add(name)
            origin=row.get('download-url','')
            if name in actual_to_base:
                base=actual_to_base[name];require(version==identity[base]['version'],'Solver attempted to replace a native package')
                require(origin.startswith(native.as_uri().rsplit('/',1)[0]+'/') or origin.startswith(supplement.as_uri().rsplit('/',1)[0]+'/'),
                        'Solver selected a public collision for a native package')
                native_names.add(base);continue
            require(name in owners and name in public_by_actual,'Solver closure contains an unapproved public collision or provider')
            record,repo,_=owners[name];control=public_by_actual[name]
            require(version==control['Version'] and origin.startswith(Path(record['index_path']).resolve().as_uri().rsplit('/',1)[0]+'/'),
                    'Solver selected an unexpected public identity')
            selected_controls[control['Base-Package']]=control
        require(protected<=native_names and set(selected)<=set(selected_controls),'Solver omitted required native/public identities')
    return selected_controls


def public_packages(registry_path,registry_sha,snapshot_sha,selected,identity,controls,protected,
                    tree,feed,apk,apk_sha,public_key,site,mirror_root=None,mirror_prefix='/indexes'):
    catalog=public_candidates(registry_path,registry_sha,snapshot_sha,identity,controls,protected,
                              apk,apk_sha,site,mirror_root,mirror_prefix)
    selected_controls=solve_public(catalog,selected,identity,protected,tree,feed,apk,public_key)
    return selected_controls,catalog['urls'],catalog['keys']


def apk_origins(index,apk,repository,identity):
    """Bind selected canonical identities to their full signed ADB row hashes."""
    fmt=sys.modules.get('package_format');require(fmt is not None,'Trusted APK decoder missing')
    result={}
    for control in fmt.index_info(index,apk=apk):
        base,item=package_identity(control)
        if base not in identity or item!=identity[base]:continue
        digest=control['APK-Raw'].get('hashes','')
        require(SHA.fullmatch(digest) and base not in result,'Invalid or duplicate indexed APK identity')
        result[base]={'repository':repository,'filename':item['name']+'-'+item['version']+'.apk','identity_sha256':digest}
    return result


def merge_supplement(identity,controls,protected,native_hashes,packages):
    """Native manifests were verified against the native bank before this merge."""
    aliases=set().union(*(provided_names(controls[name]) for name in protected))
    changed=set()
    for path,control in packages:
        base,item=package_identity(control)
        if base in protected:
            require(base in controls and control==controls[base] and sha256(path)==native_hashes[base],
                    'Supplemental feed changes a protected native package')
            continue
        require(not (provided_names(control)&aliases),'Supplemental feed provides a protected native identity')
        require(not base.startswith(('kmod-mt76','kmod-mt7915','kmod-mt7986-firmware')),'Supplemental feed contains foreign Wi-Fi stack')
        identity[base]=item;controls[base]=control;changed.add(base)
    return changed


def native_acceptance_options(args):
    path=getattr(args,'native_acceptance',None);pin=getattr(args,'native_acceptance_sha256',None)
    if path is None and pin is None:return False
    require(path is not None and isinstance(pin,str) and SHA.fullmatch(pin),
            '--native-acceptance and its explicit SHA256 must be supplied together')
    require(args.cohort=='612-recommended' and bool(getattr(args,'source',None))
            and getattr(args,'hosted_context',None) is None,
            'Native acceptance is available only with the actual recommended native source')
    return True


def promote(args):
    require(args.cohort in {'66','612-recommended','612-latest'},'Unsupported cohort')
    use_native_acceptance=native_acceptance_options(args)
    require(bool(getattr(args,'source',None)) != bool(getattr(args,'hosted_context',None)),
            'Choose exactly one actual native source or explicit hosted context')
    site=args.site_url.rstrip('/');url=urlsplit(site)
    require(url.scheme=='https' and url.hostname and not url.username and not url.password and not url.query and not url.fragment,
            'Immutable service base must be an unambiguous HTTPS URL')
    output=Path(args.output).absolute()
    require(not output.exists() and not any(p.is_symlink() for p in (output,*output.parents)),'Promotion output must be fresh')
    public_key=regular(args.public_key,16384);usign=pinned_tool(args.usign,args.usign_sha256)
    apk=pinned_tool(args.apk,args.apk_sha256) if args.apk else None
    require((args.cohort=='66') or apk is not None,'APK cohorts require an independently pinned host decoder')
    native=read_json(args.native_evidence,args.native_evidence_sha256)
    smoke=read_json(args.imagebuilder_evidence,args.imagebuilder_evidence_sha256)
    loaded=read_json(args.builder_load_receipt,args.builder_load_receipt_sha256)
    with recipe_modules(args.package_repository,args.recipe_commit) as recipe:
        require(public_key.read_bytes()==regular(recipe/'keys/repository.pub',16384).read_bytes(),
                'Production catalog key differs from the approved package recipe')
        source_profile=regular(args.source_profile)
        require(source_profile.is_relative_to(recipe/'profiles'),'Source profile must belong to the committed package recipe')
        profile,channel,snapshot_sha,files,publisher=snapshot_identity(args.snapshot,args.cohort,public_key,usign,recipe,apk,
            operator_publisher_dir=getattr(args,'operator_publisher_dir',None))
        publisher_scope=getattr(publisher,'asu_operator_publisher_scope',None)
        require(regular(Path(args.raw)/'profile.json').read_bytes()==regular(channel/'profile.json').read_bytes(),
                'Native RAW profile bytes differ from signed snapshot')
        importer=load_module(recipe/'scripts/import-release.py','promote_import')
        importer.validate_metadata(Path(args.raw),source_profile)
        hosted=None
        if getattr(args,'hosted_context',None) is not None:
            hosted_module=load_module(ROOT/'ops/hosted_context.py','promote_hosted_context')
            hosted=hosted_module.load(args.hosted_context,args.hosted_context_sha256,cohort=args.cohort,
                profile=profile,native=native,raw=args.raw,recipe=recipe)
            source=None
            hosted.validate_smoke_scope(smoke)
        else:
            source=Path(args.source).absolute()
            require(subprocess.check_output(['git','-C',str(source),'rev-parse','HEAD'],text=True).strip()==profile['firmware']['commit'],
                    'Actual native source commit differs')
        accepted_native=None
        if use_native_acceptance:
            acceptance=load_module(ROOT/'ops/native_acceptance.py','promote_native_acceptance')
            accepted_native=acceptance.verify(args.native_acceptance,args.native_acceptance_sha256,
                cohort=args.cohort,profile=profile,native=native,native_evidence=args.native_evidence,
                native_evidence_sha256=args.native_evidence_sha256,raw=args.raw,source=source,
                recipe_commit=args.recipe_commit)
        require(profile.get('asu',{}).get('enabled') is True and profile['asu'].get('cohort')==args.cohort,
                'Generation does not enable this ASU cohort')
        builder=load_module(ROOT/'ops/builder_image.py','promote_builder')
        archive=regular(args.imagebuilder_archive,16*1024**3)
        approval=builder.validate_inputs(archive,profile['imagebuilder']['sha256'],args.builder_image_approval,
                                        args.builder_image_approval_sha256,channel/'profile.json',public_key)
        require(approval['cohort']==args.cohort,'ImageBuilder approval cohort differs')
        expected_loaded={'schema_version':1,'kind':'ax6000-imagebuilder-image-load','cohort':args.cohort,
                         'build_id':profile['build_id'],'source_commit':profile['firmware']['commit'],
                         'archive_sha256':profile['imagebuilder']['sha256'],
                         'approval_receipt_sha256':args.builder_image_approval_sha256,
                         'attestation_sha256':approval['attestation_sha256'],'loaded_engine_id':builder.ROOTLESS_ENGINE,
                         'loaded_socket':builder.ROOTLESS_SOCKET,'uid':1000,'gid':1000,'flock_timeout_available':True}
        require(all(loaded.get(k)==v for k,v in expected_loaded.items()) and re.fullmatch(r'sha256:[a-f0-9]{64}',loaded.get('image_id','')),
                'Loaded builder image receipt differs from approved generation/engine')
        require(SHA.fullmatch(loaded.get('image_tar_sha256','')),'Missing loaded image archive identity')
        image_tar=regular(args.builder_image_archive,16*1024**3)
        require(sha256(image_tar)==loaded['image_tar_sha256'],'Loaded builder image archive bytes differ')
        helper=load_module(recipe/'scripts/imagebuilder.py','promote_imagebuilder')
        extra={'apk':apk,'public_apk_key':regular(args.apk_public_key,16384)} if apk and args.cohort!='66' else {}
        if extra:
            require(extra['public_apk_key'].read_bytes()==regular(recipe/'keys/repository-apk.pem',16384).read_bytes(),
                    'Production APK key differs from the approved package recipe')
        suffix='ipk' if args.cohort=='66' else 'apk'
        with tempfile.TemporaryDirectory(prefix='asu-promote-ib-') as temporary:
            unpacked=Path(temporary)/'unpacked'
            verified=helper.verify_archive(archive,profile,public_key,usign,unpacked,source=source,
                native_packages=sorted((Path(args.raw)/'bin').rglob('*.'+suffix)),**extra)
            tree=next(unpacked.iterdir())
            attestation=read_json(tree/'ax6000-imagebuilder.json')
            require(sha256(tree/'ax6000-imagebuilder.json')==approval['attestation_sha256'],'Verified IB attestation differs from approved image')
            builder.scan_tree(tree,approval)
            if hosted is not None:
                hosted.verify_tree(tree,attestation)
                overlay=hosted.overlay
            else:
                overlay=rootfs_overlay(recipe,source,profile,native,attestation)
            identity,controls=identities(attestation['packages'])
            installed,version=native_layouts(native,args.raw,profile,identity,args.cohort)
            version_number,version_code=version
            baked=regular(tree/'include/version.mk').read_text()
            require(isinstance(version_number,str) and version_number in baked and isinstance(version_code,str)
                    and re.search(r'^REVISION\s*:?=\s*'+re.escape(version_code)+r'\s*$',baked,re.M),
                    'Actual native firmware version/revision differs from baked ImageBuilder')
            roots=core_roots(tree)|CORE|VENDOR|ASU|({'opkg'} if args.cohort=='66' else {'apk-openssl','apk-mbedtls'})
            protected=set();profiles={}
            for layout,packages in installed.items():
                required=(roots&set(packages))|ASU|{name for name in packages if name.startswith('kmod-')}
                mandatory=dependency_closure(required,packages,controls);protected.update(mandatory)
                device='xiaomi_redmi-router-ax6000-'+layout
                partitions=native['layouts'][layout]['device_tree']['partitions']
                profiles[device]={'supported_devices':[device.replace('xiaomi_','xiaomi,')],
                                  'mandatory_packages':sorted(mandatory),'default_packages':sorted(packages),
                                  'max_image_size':sum(item['size'] for item in partitions.values())}
            protected.update(name for name in identity if name.startswith('kmod-'))
            native_hashes={package_identity(item['control'])[0]:item['sha256'] for item in attestation['packages']}
            feed=channel/'feeds'/profile['id']/profile['firmware']['kernel_version']
            origins=apk_origins(tree/'packages/packages.adb',apk,'native',identity) if args.cohort!='66' else {}
            packages=[(path,publisher.read_control(path,**({'apk':apk} if args.cohort!='66' else {})))
                      for path in sorted(feed.glob('*.'+suffix))]
            changed=merge_supplement(identity,controls,protected,native_hashes,packages)
            repositories=[site+'/immutable/'+snapshot_sha+'/channel/'+feed.relative_to(channel).as_posix()+('/packages.adb' if args.cohort!='66' else '')]
            keytexts=[public_key.read_text() if args.cohort=='66' else Path(args.apk_public_key).read_text()]
            indexes={}
            if args.cohort!='66':
                supplemental_origins=apk_origins(feed/'packages.adb',apk,'supplement',identity)
                require(changed<=set(supplemental_origins),'Supplemental identities are absent from the verified index')
                origins.update({base:supplemental_origins[base] for base in changed})
                indexes={'native':{'url':'file:///builder/packages/packages.adb','sha256':sha256(tree/'packages/packages.adb')},
                         'supplement':{'url':repositories[0],'sha256':sha256(feed/'packages.adb')}}
            if args.public_package or args.public_candidates:
                require(args.cohort!='66' and args.mirror_registry and args.mirror_registry_sha256,'Public APK roots require a pinned mirror registry')
                solver_pins=set().union(*(set(p['mandatory_packages']) for p in profiles.values()))
                public=public_candidates(args.mirror_registry,args.mirror_registry_sha256,snapshot_sha,
                    identity,controls,solver_pins,apk,args.apk_sha256,site,args.mirror_root,args.mirror_prefix)
                selected=(public['controls'] if args.public_candidates else
                          solve_public(public,args.public_package,identity,solver_pins,tree,feed,apk,args.apk_public_key))
                for base,control in selected.items():
                    identity[base]={'name':control['Package'],'abi':control.get('ABIVersion',''),'version':control['Version'],'tag':PUBLIC_TAG}
                origins.update({base:public['origins'][base] for base in selected});indexes.update(public['indexes'])
                repositories+=public['urls'];keytexts+=public['keys']
            smoke_evidence(smoke,Path(args.imagebuilder_evidence).parent,profile,approval['attestation_sha256'],snapshot_sha,
                           native['layouts'],installed,identity)
            feed_receipt={'schema_version':1,'kind':'asu-feed-verification','snapshot_sha256':snapshot_sha,
                          'profile_sha256':sha256(channel/'profile.json'),'build_id':profile['build_id'],
                          'kernel_version':profile['firmware']['kernel_version'],'files':files,
                          'recipe_commit':args.recipe_commit,'native_bank_archive_sha256':sha256(archive),
                          'imagebuilder_verified':verified,'package_count':len(identity)}
            if hosted is not None:
                feed_receipt['hosted_context']=hosted.scope
            if accepted_native is not None:
                feed_receipt['native_acceptance']=accepted_native
            if publisher_scope is not None:
                feed_receipt['operator_publisher']=publisher_scope
            feed_bytes=canonical(feed_receipt)
            data={'schema_version':1,'cohort':args.cohort,'build_id':profile['build_id'],'source_commit':profile['firmware']['commit'],
                  'seed':profile['asu']['seed'],'snapshot_sha256':snapshot_sha,'package_manager':'opkg' if args.cohort=='66' else 'apk',
                  'promotion':{'verified':True,'native_evidence_sha256':args.native_evidence_sha256,
                               'imagebuilder_evidence_sha256':args.imagebuilder_evidence_sha256,
                               'feed_evidence_sha256':hashlib.sha256(feed_bytes).hexdigest()},
                  'imagebuilder':{'archive_sha256':sha256(archive),'image':loaded['image_id']},
                  'firmware':{'target':'mediatek/filogic','architecture':profile['firmware']['architecture'],
                              'kernel_version':profile['firmware']['kernel_version'],'version_number':version_number,'version_code':version_code},
                  'packages':{name:item['version'] for name,item in identity.items()},'package_identities':identity,
                  'profiles':profiles,'protected_packages':sorted(protected),
                  'rootfs_overlay':overlay,
                  'repositories_conf':(('src/gz ax6000 '+repositories[0]+'\noption check_signature\n') if args.cohort=='66' else '\n'.join(repositories)+'\n'),
                  'repository_keys':list(dict.fromkeys(keytexts))}
            if accepted_native is not None:
                data['promotion']['native_acceptance_sha256']=accepted_native['native_acceptance_sha256']
            if args.cohort!='66':
                data['apk_protected_roots']=(hosted.policy['protected_roots'] if hosted is not None
                                             else apk_protected_roots(source,attestation))
                require(set(origins)==set(identity),'APK catalog origins do not cover every approved identity')
                data.update(apk_repositories=indexes,package_origins=origins)
                if args.public_candidates or args.public_package:
                    data['public_policy']={'mode':'candidates' if args.public_candidates else 'validated-subset',
                                           'distribution':public['distribution'],'tag':PUBLIC_TAG}
            payload=catalog_bytes(data);catalog_sha=hashlib.sha256(payload).hexdigest()
            # Server policy imports its stdlib-only overlay validator by package
            # name; the operator may invoke this script from any directory.
            sys.path.insert(0,str(ROOT))
            policy=load_module(ROOT/'asu/ax6000_policy.py','promote_policy')
            check=Path(temporary)/'catalog.json';check.write_bytes(payload);policy.Catalog.load(check,catalog_sha,args.cohort)
            # All validation finishes before the first persistent write.
            immutable=immutable_copy(channel,args.snapshot,files,args.store,snapshot_sha)
            output.parent.mkdir(parents=True,exist_ok=True)
            with tempfile.TemporaryDirectory(prefix='.catalog-',dir=output.parent) as staging:
                ready=Path(staging)
                write_new(ready/'catalog.json',payload);write_new(ready/'catalog.sha256',(catalog_sha+'  catalog.json\n').encode())
                write_new(ready/'feed-evidence.json',feed_bytes)
                audit={'schema_version':1,'catalog_sha256':catalog_sha,'snapshot_sha256':snapshot_sha,'immutable_path':str(immutable),
                       'recipe_commit':args.recipe_commit,'builder_load_receipt_sha256':args.builder_load_receipt_sha256,
                       'builder_image_approval_sha256':args.builder_image_approval_sha256,'service_activated':False}
                if hosted is not None:
                    audit['hosted_context']=hosted.scope
                if accepted_native is not None:
                    audit['native_acceptance']=accepted_native
                if publisher_scope is not None:
                    audit['operator_publisher']=publisher_scope
                write_new(ready/'promotion.json',canonical(audit));ready.chmod(0o555);rename_new(ready,output)
    return {'catalog':str(output/'catalog.json'),'catalog_sha256':catalog_sha,'snapshot_sha256':snapshot_sha,'service_activated':False}


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cohort',required=True,choices=('66','612-recommended','612-latest'))
    for name in ('package-repository','source-profile','snapshot','raw','imagebuilder-archive','native-evidence','imagebuilder-evidence',
                 'builder-image-approval','builder-load-receipt','builder-image-archive','public-key','usign','store','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    for name in ('recipe-commit','native-evidence-sha256','imagebuilder-evidence-sha256','builder-image-approval-sha256',
                 'builder-load-receipt-sha256','usign-sha256','site-url'):
        parser.add_argument('--'+name,required=True)
    parser.add_argument('--apk',type=Path);parser.add_argument('--apk-sha256');parser.add_argument('--apk-public-key',type=Path)
    parser.add_argument('--operator-publisher-dir',type=Path,
                        help='Explicit two-file reviewed APK publisher handoff; native recipe provenance is retained')
    context=parser.add_mutually_exclusive_group(required=True)
    context.add_argument('--source',type=Path)
    context.add_argument('--hosted-context',type=Path)
    parser.add_argument('--hosted-context-sha256')
    parser.add_argument('--native-acceptance',type=Path)
    parser.add_argument('--native-acceptance-sha256')
    parser.add_argument('--mirror-registry',type=Path);parser.add_argument('--mirror-registry-sha256')
    parser.add_argument('--mirror-root',type=Path);parser.add_argument('--mirror-prefix',default='/indexes')
    public=parser.add_mutually_exclusive_group()
    public.add_argument('--public-package',action='append',default=[])
    public.add_argument('--public-candidates',action='store_true')
    args=parser.parse_args(argv)
    try:print(json.dumps(promote(args),sort_keys=True))
    except (ValueError,OSError,KeyError,TypeError,subprocess.SubprocessError) as error:
        parser.exit(1,'Promotion refused: '+str(error)+'\n')


if __name__=='__main__':main()
