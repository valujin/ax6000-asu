"""Operator guards use real signatures/solver; fixtures never activate a service."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SPEC=importlib.util.spec_from_file_location('test_promoter',ROOT/'ops/promote.py')
promote=importlib.util.module_from_spec(SPEC);SPEC.loader.exec_module(promote)
RECIPES=Path(os.environ.get('PROMOTE_TEST_RECIPES','/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21'))
USIGN=Path(os.environ.get('USIGN','/home/valuxin/dev/owrt/stock-bootstrap-build/2026-10-21/tools/usign/build/usign'))
APK=Path(os.environ.get('APK',str(RECIPES/'task-tools/apk-3.0.5/build/src/apk')))


def ipk(path,name='userpkg'):
    control=('Package: '+name+'\nVersion: 1-r1\nArchitecture: aarch64_cortex-a53\nDepends: libc\n').encode()
    nested=io.BytesIO()
    with tarfile.open(fileobj=nested,mode='w:gz') as archive:
        info=tarfile.TarInfo('./control');info.size=len(control);archive.addfile(info,io.BytesIO(control))
    with tarfile.open(path,'w:gz') as archive:
        info=tarfile.TarInfo('./control.tar.gz');info.size=len(nested.getvalue());archive.addfile(info,io.BytesIO(nested.getvalue()))


class PromotionGuards(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name)

    def test_inventory_copy_is_exact_readonly_and_never_replaces(self):
        channel=self.root/'channel';(channel/'state').mkdir(parents=True)
        (channel/'state/lock.json').write_text('{}\n');(channel/'.nojekyll').touch()
        files=promote.inventory(channel)
        manifest={'files':files};(self.root/'snapshot-manifest.json').write_bytes(promote.canonical(manifest))
        (self.root/'snapshot-manifest.sig').write_bytes(b'fixture envelope only')
        digest=promote.sha256(self.root/'snapshot-manifest.json')
        destination=promote.immutable_copy(channel,self.root,files,self.root/'store',digest)
        self.assertEqual(promote.inventory(destination/'channel'),files)
        self.assertEqual((destination/'channel/state/lock.json').stat().st_mode&0o777,0o444)
        with self.assertRaisesRegex(ValueError,'already exists'):
            promote.immutable_copy(channel,self.root,files,self.root/'store',digest)
        with self.assertRaises(FileExistsError):promote.write_new(destination/'channel/state/lock.json',b'changed')

    def test_copy_refuses_links_and_postverification_drift(self):
        tree=self.root/'channel';tree.mkdir();(tree/'safe').write_bytes(b'original')
        files=promote.inventory(tree);(tree/'safe').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'changed during'):
            promote.immutable_copy(tree,self.root,files,self.root/'store','a'*64)
        (tree/'link').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'links'):promote.inventory(tree)

    def test_native_defaults_and_dependency_closure_come_from_installed_manifest(self):
        identity={name:{'name':name,'abi':'','version':'1-r1','tag':''} for name in ('base-files','libc','libgcc','tailscale')}
        manifest=self.root/'native.manifest';manifest.write_text('base-files - 1-r1\nlibc - 1-r1\nlibgcc - 1-r1\n')
        installed=promote.parse_manifest(manifest,identity)
        controls={'base-files':{'Package':'base-files','Depends':'libc'},'libc':{'Package':'libc','Depends':'libgcc'},'libgcc':{'Package':'libgcc'}}
        self.assertNotIn('tailscale',installed)
        self.assertEqual(promote.dependency_closure({'base-files'},installed,controls),set(installed))
        manifest.write_text('base-files - 2-r1\n')
        with self.assertRaisesRegex(ValueError,'version differs'):promote.parse_manifest(manifest,identity)

    def test_daily_userspace_update_preserves_native_default_names_and_core_bytes(self):
        controls={'libc':{'Package':'libc','Version':'1-r1'},
                  'pbr':{'Package':'pbr','Version':'1-r1','Depends':'libc'}}
        identity,_=promote.identities([{'control':c} for c in controls.values()])
        manifest=self.root/'native.manifest';manifest.write_text('libc - 1-r1\npbr - 1-r1\n')
        native=promote.parse_manifest(manifest,identity)
        update=self.root/'pbr.apk';update.write_bytes(b'new approved daily archive')
        changed=promote.merge_supplement(identity,controls,{'libc'},{'libc':'a'*64},
                                        [(update,{'Package':'pbr','Version':'2-r1','Depends':'libc'})])
        self.assertEqual(changed,{'pbr'})
        target=self.root/'target.manifest';target.write_text('libc - 1-r1\npbr - 2-r1\n')
        self.assertEqual(set(promote.parse_manifest(target,identity)),set(native))
        with self.assertRaisesRegex(ValueError,'version differs'):promote.parse_manifest(manifest,identity)
        with self.assertRaisesRegex(ValueError,'protected native'):
            promote.merge_supplement(identity,controls,{'libc'},{'libc':'a'*64},
                                     [(update,{'Package':'libc','Version':'2-r1'})])

    def test_catalog_encoding_is_compact_bounded_and_lossless(self):
        data={'packages':{'ordinary-app':'1-r1'},'unicode':'fixture'}
        payload=promote.catalog_bytes(data)
        self.assertEqual(json.loads(payload),data);self.assertLess(len(payload),len(promote.canonical(data)))
        with self.assertRaisesRegex(ValueError,'8 MiB'):
            promote.catalog_bytes({'oversized':'a'*promote.MAX_CATALOG})

    def test_opkg_and_apk_strip_only_the_exact_declared_abi_suffix(self):
        for control in ({'Package':'libubox20240329','ABIVersion':'20240329','Version':'1-r1'},
                        {'Package':'libubox20240329','Base-Package':'libubox','ABIVersion':'20240329','Version':'1-r1'}):
            base,identity=promote.package_identity(control)
            self.assertEqual(base,'libubox');self.assertEqual(identity['name'],'libubox20240329')
            self.assertEqual(identity['abi'],'20240329')
        self.assertEqual(promote.package_identity({'Package':'libfoo42','Version':'1-r1'})[0],'libfoo42')
        self.assertEqual(promote.package_identity({'Package':'libusb-1.0-0','ABIVersion':'-0','Version':'1-r1'})[0],'libusb-1.0')
        with self.assertRaisesRegex(ValueError,'ABI suffix'):
            promote.package_identity({'Package':'libfoo42','ABIVersion':'43','Version':'1-r1'})

    def test_receipt_json_requires_independent_digest_and_unique_finite_fields(self):
        path=self.root/'receipt.json';path.write_text('{"approved":true}')
        with self.assertRaisesRegex(ValueError,'SHA256'):promote.read_json(path,'a'*64)
        for content in ('{"x":1,"x":2}','{"x":NaN}'):
            path.write_text(content)
            with self.assertRaises(ValueError):promote.read_json(path,promote.sha256(path))

    def test_dirty_tracked_native_asset_invalidates_the_approved_recipe(self):
        repository=self.root/'recipe';repository.mkdir()
        for directory in ('scripts','keys','profiles','files/asu-client'):(repository/directory).mkdir(parents=True)
        asset=repository/'files/asu-client/client.js';asset.write_text('const native = true;\n')
        commands=[['git','init','--quiet'],['git','add','files'],
                  ['git','-c','user.name=Fixture','-c','user.email=fixture@example.invalid','commit','--quiet','-m','Unactivated fixture asset']]
        for command in commands:subprocess.run(command,cwd=repository,check=True,capture_output=True)
        commit=subprocess.check_output(['git','rev-parse','HEAD'],cwd=repository,text=True).strip()
        with promote.recipe_modules(repository,commit):pass
        asset.write_text('const native = false;\n')
        with self.assertRaisesRegex(ValueError,'committed bytes'):
            with promote.recipe_modules(repository,commit):pass

    def test_smoke_receipt_binds_real_artifact_bytes_layout_and_kernel(self):
        kernel='a'*64;archive='b'*64;attestation='c'*64;snapshot='d'*64
        identity={'kernel':{'name':'kernel','abi':'','version':'6.6.133~'+'e'*32+'-r1','tag':''},
                  'libc':{'name':'libc','abi':'','version':'1-r1','tag':''}}
        profile={'build_id':'native','imagebuilder':{'sha256':archive},
                 'firmware':{'commit':'f'*40,'architecture':'aarch64_cortex-a53','kernel_version':identity['kernel']['version']}}
        contents={'info':b'xiaomi_redmi-router-ax6000-stock\n',
                  'manifest':('kernel - '+identity['kernel']['version']+'\nlibc - 1-r1\n').encode(),
                  'image':b'unit fixture, not firmware',
                  'metadata':json.dumps({'supported_devices':['xiaomi,redmi-router-ax6000-stock'],
                     'version':{'target':'mediatek/filogic','board':'xiaomi_redmi-router-ax6000-stock'}}).encode()}
        artifacts={}
        for name,data in contents.items():
            path=self.root/name;path.write_bytes(data)
            artifacts[name]={'path':name,'size':len(data),'sha256':promote.sha256(path)}
        record={**artifacts,'exit_codes':{'info':0,'manifest':0,'image':0},'kernel_sha256':kernel}
        proof={'schema_version':1,'kind':'ax6000-imagebuilder-smoke','identity':{'build_id':'native','source_commit':'f'*40,
                   'architecture':'aarch64_cortex-a53','kernel_version':identity['kernel']['version'],'target':'mediatek/filogic'},
               'archive_sha256':archive,'attestation_sha256':attestation,'snapshot_sha256':snapshot,'layouts':{'stock':record}}
        native={'stock':{'kernel':{'sha256':kernel}}};installed={'stock':dict((name,value['version']) for name,value in identity.items())}
        promote.smoke_evidence(proof,self.root,profile,attestation,snapshot,native,installed,identity)
        for mutate in (lambda p:p.update(snapshot_sha256='0'*64),
                       lambda p:p['layouts']['stock']['exit_codes'].update(image=1),
                       lambda p:p['layouts']['stock'].update(kernel_sha256='0'*64),
                       lambda p:p['layouts']['stock']['image'].update(sha256='0'*64)):
            candidate=copy.deepcopy(proof);mutate(candidate)
            with self.assertRaises(ValueError):
                promote.smoke_evidence(candidate,self.root,profile,attestation,snapshot,native,installed,identity)

    def test_overlay_uses_only_reviewed_native_paths_and_all_layout_evidence(self):
        fingerprint='a'*16
        paths={'etc/asu-cohort.json':0o644,'etc/uci-defaults/99-ax6000-asu':0o755,
               'usr/sbin/ax6000-install-feed':0o755,'etc/opkg/distfeeds.conf':0o644,
               'etc/opkg/keys/'+fingerprint:0o644}
        proof={}
        for name,mode in paths.items():
            path=self.root/'files'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name);path.chmod(mode)
            proof[name]={'sha256':promote.sha256(path),'mode':f'{mode:04o}'}
        extra=self.root/'files/etc/rc.local';extra.write_text('unexpected code');extra.chmod(0o755)
        native={'layouts':{layout:{'root':{'repository_files':copy.deepcopy(proof)}} for layout in ('stock','mtkuboot')}}
        overlay=promote.overlay_records(self.root,{'package_manager':'opkg'},native,fingerprint)
        self.assertEqual(set(overlay),set(paths));self.assertNotIn('etc/rc.local',overlay)
        self.assertEqual(overlay['usr/sbin/ax6000-install-feed']['mode'],0o755)
        native['layouts']['mtkuboot']['root']['repository_files']['etc/opkg/distfeeds.conf']['sha256']='b'*64
        with self.assertRaisesRegex(ValueError,'overlay bytes/mode differ'):
            promote.overlay_records(self.root,{'package_manager':'opkg'},native,fingerprint)
        native['layouts']['mtkuboot']['root']['repository_files']=copy.deepcopy(proof)
        (self.root/'files/etc/opkg/distfeeds.conf').unlink();(self.root/'files/etc/opkg/distfeeds.conf').symlink_to('/etc/passwd')
        with self.assertRaisesRegex(ValueError,'linked'):
            promote.overlay_records(self.root,{'package_manager':'opkg'},native,fingerprint)

    def test_apk_overlay_never_copies_a_native_protected_list(self):
        paths={'etc/asu-cohort.json':0o644,'etc/uci-defaults/99-ax6000-asu':0o755,
               'usr/sbin/ax6000-install-feed':0o755,'etc/apk/repositories.d/distfeeds.list':0o644,
               'etc/apk/repositories.d/customfeeds.list':0o644,'etc/apk/keys/repository-apk.pem':0o644,
               'etc/ax6000/repository.pub':0o644}
        proof={}
        for name,mode in paths.items():
            path=self.root/'files'/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(name);path.chmod(mode)
            proof[name]={'sha256':promote.sha256(path),'mode':mode}
        (self.root/'files/etc/apk/ax6000-protected.list').write_text('native-only=1-r1\n')
        native={'layouts':{'stock':{'root':{'repository_files':proof}}}}
        overlay=promote.overlay_records(self.root,{'package_manager':'apk'},native,'')
        self.assertEqual(set(overlay),set(paths));self.assertNotIn('etc/apk/ax6000-protected.list',overlay)

    def test_apk_guard_roots_come_from_exact_attested_policy_not_asu_mandatory_packages(self):
        path=self.root/'ax6000-apk-world-policy.json'
        policy={'schema_version':1,'package_manager':'apk','cohort':'612-recommended',
                'protected_roots':['base-files','busybox','kernel','libc']}
        path.write_bytes(promote.canonical(policy))
        attestation={'context':[{'path':path.name,'sha256':promote.sha256(path),'size':path.stat().st_size}]}
        roots=promote.apk_protected_roots(self.root,attestation)
        self.assertEqual(roots,policy['protected_roots']);self.assertNotIn('luci-app-attendedsysupgrade',roots)
        path.write_text('{}\n')
        with self.assertRaisesRegex(ValueError,'attested native policy'):
            promote.apk_protected_roots(self.root,attestation)
        policy['protected_roots']=['libc','kernel'];path.write_bytes(promote.canonical(policy))
        attestation['context'][0].update(sha256=promote.sha256(path),size=path.stat().st_size)
        with self.assertRaisesRegex(ValueError,'canonical APK protected roots'):
            promote.apk_protected_roots(self.root,attestation)

    @unittest.skipUnless((RECIPES/'packages/scripts/asu_client.py').is_file(),'trusted package recipe is required')
    def test_committed_opkg_renderers_recheck_actual_overlay_without_writing(self):
        recipe=RECIPES/'packages';old_path=list(sys.path);saved={}
        for name in ('prepare','publish'):
            if name in sys.modules:saved[name]=sys.modules.pop(name)
        sys.path.insert(0,str(recipe/'scripts'))
        try:
            renderer=promote.load_module(recipe/'scripts/prepare-firmware.py','test_native_renderer')
            client=promote.load_module(recipe/'scripts/asu_client.py','test_native_asu')
            profile={'asu':{'enabled':True,'cohort':'66','server_url':'https://asu.ezon.by/66','seed':'a'*64}}
            renderer.repository_files(self.root);client.configure(profile,self.root)
            files=list((self.root/'files').rglob('*'))
            before={p.relative_to(self.root/'files').as_posix():p.read_bytes() for p in files if p.is_file()}
            proof={name:{'sha256':hashlib.sha256(data).hexdigest(),
                          'mode':f'{(self.root/"files"/name).stat().st_mode&0o7777:04o}'} for name,data in before.items()}
            overlay=promote.rootfs_overlay(recipe,self.root,profile,{'layouts':{'stock':{'root':{'repository_files':proof}}}}, {})
            self.assertEqual(set(overlay),set(before))
            self.assertEqual(before,{p.relative_to(self.root/'files').as_posix():p.read_bytes() for p in files if p.is_file()})
            installer=self.root/'files/usr/sbin/ax6000-install-feed';installer.write_text('#!/bin/sh\nexit 0\n')
            with self.assertRaisesRegex(ValueError,'reviewed defaults'):
                promote.rootfs_overlay(recipe,self.root,profile,{'layouts':{'stock':{'root':{'repository_files':proof}}}}, {})
        finally:
            for name in ('prepare','publish'):sys.modules.pop(name,None)
            sys.modules.update(saved);sys.path[:]=old_path

    def test_immutable_install_rejects_racing_destination(self):
        source=self.root/'source';source.mkdir();destination=self.root/'destination';destination.mkdir()
        with self.assertRaises(FileExistsError):promote.rename_new(source,destination)
        self.assertTrue(source.is_dir())


@unittest.skipUnless(USIGN.is_file() and (RECIPES/'packages/scripts/publish.py').is_file(),'trusted host usign/recipe required')
class SignedSnapshots(unittest.TestCase):
    def setUp(self):
        PromotionGuards.setUp(self);self.key=self.root/'private';self.public=self.root/'public'
        subprocess.run([str(USIGN),'-G','-s',str(self.key),'-p',str(self.public)],check=True,capture_output=True)
        self.publisher=promote.load_module(RECIPES/'packages/scripts/publish.py','promote_test_publisher')
        self.profile={'id':'redmi-ax6000','enabled':True,'build_id':'native-fixture','sdk':{'sha256':'a'*64},
                      'firmware':{'architecture':'aarch64_cortex-a53','kernel_version':'6.6.133~'+'a'*32+'-r1'}}
        raw=self.root/'raw';raw.mkdir();ipk(raw/'userpkg.ipk')
        self.tree=self.root/'snapshot'
        feed=self.publisher.stage_feed(raw,self.tree,self.profile)
        self.sign(feed/'Packages',feed/'Packages.sig')
        (self.tree/'profile.json').write_text(json.dumps(self.profile));(self.tree/'state').mkdir()
        lock={'profile_sha256':promote.sha256(self.tree/'profile.json'),'firmware':self.profile['firmware'],'sdk':self.profile['sdk']}
        (self.tree/'state/lock.json').write_text(json.dumps(lock));shutil.copyfile(self.public,self.tree/'repository.pub')
        manifest={'schema_version':1,'cohort':'66','profile_id':self.profile['id'],'build_id':self.profile['build_id'],
                  'kernel_version':self.profile['firmware']['kernel_version'],'files':promote.inventory(self.tree)}
        (self.tree/'snapshot-manifest.json').write_bytes(promote.canonical(manifest))
        self.sign(self.tree/'snapshot-manifest.json',self.tree/'snapshot-manifest.sig')

    def sign(self,message,signature):
        subprocess.run([str(USIGN),'-S','-m',str(message),'-s',str(self.key),'-x',str(signature)],check=True,capture_output=True)

    def test_real_signed_generic_66_snapshot_and_packages_verify(self):
        profile,tree,digest,files,_=promote.snapshot_identity(self.tree,'66',self.public,USIGN,RECIPES/'packages')
        self.assertEqual(profile,self.profile);self.assertEqual(tree,self.tree)
        self.assertEqual(digest,promote.sha256(self.tree/'snapshot-manifest.json'))
        self.assertNotIn('snapshot-manifest.json',{entry['path'] for entry in files})

    def test_modified_package_or_foreign_signature_is_rejected(self):
        package=next(self.tree.rglob('*.ipk'));package.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError,'inventory differs'):
            promote.snapshot_identity(self.tree,'66',self.public,USIGN,RECIPES/'packages')
        other=self.root/'other.pub'
        subprocess.run([str(USIGN),'-G','-s',str(self.root/'other.private'),'-p',str(other)],check=True,capture_output=True)
        with self.assertRaises(subprocess.CalledProcessError):
            promote.snapshot_identity(self.tree,'66',other,USIGN,RECIPES/'packages')


@unittest.skipUnless(APK.is_file() and (RECIPES/'packages612/scripts/package_format.py').is_file(),'trusted host APK3 required')
class PublicSolver(unittest.TestCase):
    def setUp(self):
        PromotionGuards.setUp(self)
        self.format=promote.load_module(RECIPES/'packages612/scripts/package_format.py','package_format')
        self.tree=self.root/'builder';(self.tree/'packages').mkdir(parents=True);(self.tree/'keys').mkdir()
        self.private=self.root/'private.pem';self.public=self.root/'public.pem'
        self.command('openssl','genpkey','-algorithm','EC','-pkeyopt','ec_paramgen_curve:prime256v1','-out',self.private)
        self.command('openssl','pkey','-in',self.private,'-pubout','-out',self.public)
        shutil.copyfile(self.public,self.tree/'keys/native.pem')
        self.native=self.package(self.tree/'packages','libc')
        self.index(self.tree/'packages',[self.native])
        self.feed=self.root/'supplement';self.feed.mkdir();self.index(self.feed,[self.package(self.feed,'native-extra')])
        self.official=self.root/'official';self.official.mkdir()
        self.index(self.official,[self.package(self.official,'userapp',depends='libc'),self.package(self.official,'foreign',depends='nonexistent')])
        self.snapshot='a'*64
        record={'feed':'packages','distribution':'immortalwrt','index_path':str(self.official/'packages.adb'),
                'index_sha256':promote.sha256(self.official/'packages.adb'),'key_path':str(self.public),'key_sha256':promote.sha256(self.public),
                'base_url':'https://downloads.immortalwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/'}
        self.registry=self.root/'registry.json';self.registry.write_text(json.dumps({'schema_version':1,'snapshots':[{'snapshot_sha256':self.snapshot,'repositories':[record]}]}))
        self.identity={'libc':{'name':'libc','abi':'','version':'1-r1','tag':''}}
        self.controls={'libc':self.format.read_control(self.native,apk=APK)}

    def command(self,*args):
        return subprocess.run(list(map(str,args)),check=True,capture_output=True,timeout=30)

    def package(self,directory,name,depends=None,provides=None,abi=None):
        payload=self.root/('payload-'+directory.name+'-'+name);payload.mkdir();(payload/'fixture').write_text(name)
        path=directory/(name+'-1-r1.apk')
        args=[APK,'--no-network','mkpkg','--info','name:'+name,'--info','version:1-r1','--info','arch:aarch64_cortex-a53',
              '--files',payload,'--output',path]
        if depends:args+=['--info','depends:'+depends]
        if provides:args+=['--info','provides:'+provides]
        if abi:args+=['--info','tags:openwrt:abiversion='+abi]
        self.command(*args);return path

    def index(self,directory,packages):
        self.command(APK,'--no-network','mkndx','--allow-untrusted','--sign',self.private,'--output',directory/'packages.adb',*packages)

    def select(self,names):
        return promote.public_packages(self.registry,promote.sha256(self.registry),self.snapshot,names,self.identity,self.controls,
                                      {'libc'},self.tree,self.feed,APK,promote.sha256(APK),self.public,'https://asu.ezon.by')

    def test_native_readonly_solver_selects_userspace_and_preserves_native_provider(self):
        controls,urls,keys=self.select(['userapp'])
        self.assertEqual(set(controls),{'userapp'});self.assertEqual(len(keys),1)
        self.assertTrue(urls[0].startswith('@public '))
        self.assertIn('/immutable/'+self.snapshot+'/public/',urls[0])
        self.assertFalse((self.root/'cache').exists())

    def test_openwrt_whole_snapshot_alternative_uses_the_same_native_guards(self):
        registry=json.loads(self.registry.read_text())
        record=registry['snapshots'][0]['repositories'][0]
        record.update(distribution='openwrt',base_url='https://downloads.openwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/packages/')
        self.registry.write_text(json.dumps(registry))
        candidates=promote.public_candidates(self.registry,promote.sha256(self.registry),self.snapshot,
            self.identity,self.controls,{'libc'},APK,promote.sha256(APK),'https://asu.ezon.by')
        self.assertEqual(candidates['distribution'],'openwrt')
        controls,urls,_=self.select(['userapp'])
        self.assertEqual(set(controls),{'userapp'});self.assertTrue(urls[0].startswith('@public '))
        with self.assertRaisesRegex(ValueError,'collides'):self.select(['libc'])
        with self.assertRaisesRegex(ValueError,'solver|closure'):self.select(['foreign'])

    def test_frozen_snapshot_rejects_mixed_public_distributions(self):
        registry=json.loads(self.registry.read_text())
        repositories=registry['snapshots'][0]['repositories']
        other=dict(repositories[0]);other.update(feed='base',distribution='openwrt',
            base_url='https://downloads.openwrt.org/releases/25.12.0/packages/aarch64_cortex-a53/base/')
        repositories.append(other);self.registry.write_text(json.dumps(registry))
        with self.assertRaisesRegex(ValueError,'mix public distributions'):
            promote.public_candidates(self.registry,promote.sha256(self.registry),self.snapshot,
                self.identity,self.controls,{'libc'},APK,promote.sha256(APK),'https://asu.ezon.by')

    def test_candidates_keep_unlisted_apps_and_mutually_exclusive_alternatives(self):
        packages=[self.official/'userapp-1-r1.apk',self.official/'foreign-1-r1.apk']
        packages += [self.package(self.official,'ordinary-app',depends='libc'),
                     self.package(self.official,'alternative-a',depends='libc !alternative-b'),
                     self.package(self.official,'alternative-b',depends='libc !alternative-a')]
        self.index(self.official,packages)
        registry=json.loads(self.registry.read_text())
        registry['snapshots'][0]['repositories'][0]['index_sha256']=promote.sha256(self.official/'packages.adb')
        self.registry.write_text(json.dumps(registry))
        candidates=promote.public_candidates(self.registry,promote.sha256(self.registry),self.snapshot,
            self.identity,self.controls,{'libc'},APK,promote.sha256(APK),'https://asu.ezon.by')
        self.assertEqual(set(candidates['controls']),{'userapp','foreign','ordinary-app','alternative-a','alternative-b'})
        for name in ('ordinary-app','alternative-a','alternative-b'):
            selected,_,_=self.select([name]);self.assertEqual(set(selected),{name})
        with self.assertRaisesRegex(ValueError,'solver|closure'):self.select(['alternative-a','alternative-b'])
        origin=candidates['origins']['ordinary-app']
        raw=self.format.index_info(self.official/'packages.adb',APK)
        expected=next(row['APK-Raw']['hashes'] for row in raw if row['Package']=='ordinary-app')
        self.assertEqual(origin,{'repository':'public-packages','filename':'ordinary-app-1-r1.apk','identity_sha256':expected})
        self.assertEqual(candidates['indexes']['public-packages']['sha256'],promote.sha256(self.official/'packages.adb'))

    def test_native_index_origins_bind_full_index_identity_not_archive_digest(self):
        origins=promote.apk_origins(self.tree/'packages/packages.adb',APK,'native',self.identity)
        self.assertEqual(set(origins),{'libc'})
        self.assertEqual(origins['libc']['filename'],'libc-1-r1.apk')
        self.assertRegex(origins['libc']['identity_sha256'],r'^[a-f0-9]{64}$')
        self.assertNotEqual(origins['libc']['identity_sha256'],promote.sha256(self.native))

    def test_candidates_exclude_managers_kmods_native_providers_and_ambiguous_abis(self):
        packages=[self.official/'userapp-1-r1.apk',self.official/'foreign-1-r1.apk']
        packages += [self.package(self.official,'libc'),self.package(self.official,'public-libc',provides='libc=1-r1'),
                     self.package(self.official,'apk-openssl'),self.package(self.official,'kmod-fixture'),
                     self.package(self.official,'kmod-user',depends='kmod-fixture'),
                     self.package(self.official,'libambiguous2025',abi='2025'),
                     self.package(self.official,'libambiguous2026',abi='2026'),
                     self.package(self.official,'libapproved2026',abi='2026')]
        self.index(self.official,packages)
        registry=json.loads(self.registry.read_text())
        registry['snapshots'][0]['repositories'][0]['index_sha256']=promote.sha256(self.official/'packages.adb')
        self.registry.write_text(json.dumps(registry))
        candidates=promote.public_candidates(self.registry,promote.sha256(self.registry),self.snapshot,
            self.identity,self.controls,{'libc'},APK,promote.sha256(APK),'https://asu.ezon.by')
        self.assertEqual(set(candidates['controls']),{'userapp','foreign','libapproved'})
        self.assertEqual(candidates['controls']['libapproved']['Package'],'libapproved2026')
        self.assertEqual(candidates['controls']['libapproved']['ABIVersion'],'2026')

    @unittest.skipUnless((RECIPES/'packages612/tests/test_apk_world.py').is_file(),'native guard fixture required')
    def test_native_public_world_tag_survives_install_guard_and_repository_reuse(self):
        fixtures=promote.load_module(RECIPES/'packages612/tests/test_apk_world.py','test_actual_tag_world')
        fixtures.APK=str(APK)
        native=fixtures.RealApkGuardTests()
        native.setUp();self.addCleanup(native.doCleanups)
        guard=fixtures.guard();guard.pin_root(native.root,APK,native.policy)
        protected=native.root/'etc/apk/ax6000-protected.list';before=protected.read_bytes()
        repositories=self.root/'router-repositories'
        repositories.write_text('@public '+str(self.official/'packages.adb')+'\n')
        command=[APK,'--root',native.root,'--arch','aarch64_cortex-a53','--no-network',
                 '--repositories-file',repositories,'--keys-dir',self.tree/'keys','--no-cache']
        self.command(*command,'--no-scripts','--no-commit-hooks','--usermode','add','userapp@public=1-r1')
        guard.pin_root(native.root,APK,native.policy)
        world=(native.root/'etc/apk/world').read_text()
        self.assertIn('userapp@public=1-r1\n',world);self.assertNotIn('immortal_public',world)
        self.assertEqual(protected.read_bytes(),before)
        self.command(*command,'update')
        self.command(*command,'--no-scripts','--no-commit-hooks','--usermode','add','--simulate','userapp@public=1-r1')

    def test_unsatisfied_solver_exit_zero_is_still_rejected(self):
        with self.assertRaisesRegex(ValueError,'solver|closure'):
            self.select(['foreign'])

    def test_native_name_collision_cannot_be_requested_from_public(self):
        with self.assertRaisesRegex(ValueError,'collides'):
            self.select(['libc'])

    def test_container_registry_paths_rebase_only_inside_the_approved_mount(self):
        registry=json.loads(self.registry.read_text())
        record=registry['snapshots'][0]['repositories'][0]
        record.update(index_path='/indexes/official/packages.adb',key_path='/indexes/public.pem')
        self.registry.write_text(json.dumps(registry))
        controls,urls,_=promote.public_packages(self.registry,promote.sha256(self.registry),self.snapshot,['userapp'],
            self.identity,self.controls,{'libc'},self.tree,self.feed,APK,promote.sha256(APK),self.public,'https://asu.ezon.by',self.root)
        self.assertEqual(set(controls),{'userapp'})
        record['key_path']='/etc/foreign.pem';self.registry.write_text(json.dumps(registry))
        with self.assertRaisesRegex(ValueError,'container index prefix'):
            promote.public_packages(self.registry,promote.sha256(self.registry),self.snapshot,['userapp'],
                self.identity,self.controls,{'libc'},self.tree,self.feed,APK,promote.sha256(APK),self.public,'https://asu.ezon.by',self.root)


if __name__=='__main__':unittest.main()
