"""Use actual legacy keyring metadata and real tiny signed APK snapshots."""
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
spec=importlib.util.spec_from_file_location('operator_promote',ROOT/'ops/promote.py')
promote=importlib.util.module_from_spec(spec);spec.loader.exec_module(promote)
TASK=Path(os.environ.get('PROMOTE_TEST_RECIPES','/home/valuxin/dev/owrt/asu-pbr-db-2026-10-21'))
EA=TASK/'native612recommended-fixed-feeds/recipe-ea6de11283a6'
PUBLISHER=Path(os.environ.get('PROMOTE_TEST_OPERATOR_PUBLISHER',str(TASK/'publication612-preparation-v6/publisher')))
APK=Path(os.environ.get('APK',str(TASK/'task-tools/apk-3.0.5/build/src/apk')))
USIGN=Path(os.environ.get('USIGN','/home/valuxin/dev/owrt/stock-bootstrap-build/2026-10-21/tools/usign/build/usign'))


@unittest.skipUnless((PUBLISHER/'publish.py').is_file(),'reviewed operator source fixture required')
class PublisherClosure(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.publisher=self.root/'publisher';shutil.copytree(PUBLISHER,self.publisher)

    def test_literal_two_file_closure_metadata_and_no_bytecode_writes(self):
        old=sys.dont_write_bytecode
        sys.dont_write_bytecode=False
        try:
            publisher=promote.reviewed_operator_publisher(self.publisher,'612-recommended')
            publisher.package_format()
            self.assertFalse(sys.dont_write_bytecode)
        finally:sys.dont_write_bytecode=old
        self.assertEqual({p.name for p in self.publisher.iterdir()},{'publish.py','package_format.py'})
        scope=publisher.asu_operator_publisher_scope
        self.assertEqual(set(scope['files']),{'publish.py','package_format.py'})
        self.assertEqual(scope['role'],'reviewed-operator-publisher')
        self.assertFalse(scope['native_producer_replaced'])
        control=json.loads((ROOT/'ops/tests/fixtures/native-openwrt-keyring-control.json').read_text())['control']
        profile={'firmware':{'architecture':'aarch64_cortex-a53','kernel_version':'6.12.108~'+'a'*32+'-r1'}}
        self.assertIn('lede-keyring',publisher.native_provider_names(control,profile))
        self.assertNotIn('lede-keyring',publisher.APK_PROTECTED)
        for base,provided in [('usign','lede-keyring'),('openwrt-keyring','foreign-keyring')]:
            bad={**control,'Base-Package':base,'Package':base,'APK-Name':base,'Provides':provided}
            with self.assertRaisesRegex(ValueError,'unrelated name'):publisher.native_provider_names(bad,profile)

    def test_unreviewed_bytes_siblings_links_and_66_refused_before_load(self):
        original=(self.publisher/'publish.py').read_bytes()
        (self.publisher/'publish.py').write_bytes(original.replace(b'APK_PROTECTED',b'APK_PROTECTEX'))
        with self.assertRaisesRegex(ValueError,'checksum|closure'):promote.reviewed_operator_publisher(self.publisher,'612-recommended')
        (self.publisher/'publish.py').write_bytes(original)
        extra=self.publisher/'extra.py';extra.write_text('raise AssertionError("must not execute")')
        with self.assertRaisesRegex(ValueError,'sibling|closure'):promote.reviewed_operator_publisher(self.publisher,'612-recommended')
        extra.unlink();original_format=(self.publisher/'package_format.py').read_bytes()
        (self.publisher/'package_format.py').unlink();(self.publisher/'package_format.py').symlink_to(PUBLISHER/'package_format.py')
        with self.assertRaisesRegex(ValueError,'linked'):promote.reviewed_operator_publisher(self.publisher,'612-recommended')
        (self.publisher/'package_format.py').unlink();(self.publisher/'package_format.py').write_bytes(original_format)
        with self.assertRaisesRegex(ValueError,'APK cohorts'):promote.reviewed_operator_publisher(self.publisher,'66')
        (self.publisher/'package_format.py').unlink()
        with self.assertRaisesRegex(ValueError,'closure|sibling'):promote.reviewed_operator_publisher(self.publisher,'612-recommended')


@unittest.skipUnless((EA/'tests/test_publish_apk.py').is_file() and PUBLISHER.is_dir() and APK.is_file() and USIGN.is_file(),
                     'frozen EA and trusted APK/usign fixture required')
class SignedOperatorSnapshot(unittest.TestCase):
    def setUp(self):
        previous_path=list(sys.path);saved=sys.modules.get('test_channel_snapshot')
        sys.path.insert(0,str(EA/'tests'))
        self.fixtures=promote.load_module(EA/'tests/test_channel_snapshot.py','test_channel_snapshot')
        apk_fixture=promote.load_module(EA/'tests/test_publish_apk.py','operator_apk_fixtures')
        sys.path[:]=previous_path
        if saved is None:sys.modules.pop('test_channel_snapshot',None)
        else:sys.modules['test_channel_snapshot']=saved
        self.fixtures.USIGN=str(USIGN);apk_fixture.APK=str(APK);apk_fixture.USIGN=str(USIGN)
        # Fixture construction uses the exact reviewed tool; the tested verifier
        # still loads the original EA snapshot code and its complete validators.
        apk_fixture.publisher=promote.load_module(PUBLISHER/'publish.py','operator_fixture_publisher')
        self.fixture=apk_fixture.APKPublication();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        self.root=self.fixture.root
        control=json.loads((ROOT/'ops/tests/fixtures/native-openwrt-keyring-control.json').read_text())['control']
        self.fixture.package('openwrt-keyring',version=control['Version'],provides=' '.join(control['APK-Raw']['provides']))
        self.fixture.channel()
        self.snapshot=self.root/'envelope';self.snapshot.mkdir()
        shutil.move(str(self.fixture.tree),self.snapshot/'channel');self.fixture.tree=self.snapshot/'channel'
        self.seal()

    def seal(self):
        profile=self.fixture.profile
        manifest={'schema_version':1,'profile_id':profile['id'],'build_id':profile['build_id'],
                  'kernel_version':profile['firmware']['kernel_version'],'files':promote.inventory(self.fixture.tree)}
        (self.snapshot/'snapshot-manifest.json').write_bytes(promote.canonical(manifest))
        self.fixture.fixture.sign(self.snapshot/'snapshot-manifest.json',self.snapshot/'snapshot-manifest.sig')

    def verify(self,**kwargs):
        return promote.snapshot_identity(self.snapshot,'612-recommended',self.fixture.fixture.public,USIGN,EA,APK,**kwargs)

    def test_default_reproduces_actual_failure_and_explicit_handoff_passes_full_validation(self):
        with self.assertRaisesRegex(ValueError,'unrelated name'):self.verify()
        profile,_,_,_,publisher=self.verify(operator_publisher_dir=PUBLISHER)
        self.assertEqual(profile,self.fixture.profile)
        self.assertTrue(publisher.asu_operator_publisher_scope)
        validator=sys.modules['promote_snapshot']
        self.assertIs(validator.module('publish'),publisher)
        self.assertEqual(Path(validator.module('package_format').__file__),EA/'scripts/package_format.py')
        self.assertEqual(Path(validator.module('firmware_layouts').__file__),EA/'scripts/firmware_layouts.py')
        # The legacy recipe was not changed or globally patched by the handoff.
        with self.assertRaisesRegex(ValueError,'unrelated name'):self.verify()
        validator=sys.modules['promote_snapshot']
        original=validator.module('publish')
        self.assertNotIn('lede-keyring',getattr(original,'APK_COMPAT_PROVIDERS',{}).get('openwrt-keyring',set()))

    def test_other_native_validation_and_signatures_still_reject(self):
        inventory=self.fixture.tree/'native-providers.json';data=json.loads(inventory.read_text())
        record=next(row for row in data['packages'] if row['Base-Package']=='openwrt-keyring')
        record['Provides']='unknown-keyring';inventory.write_text(json.dumps(data));self.seal()
        with self.assertRaisesRegex(ValueError,'unrelated name'):self.verify(operator_publisher_dir=PUBLISHER)
        (self.fixture.tree/'profile.sig').write_bytes(b'bad signature');self.seal()
        with self.assertRaises(subprocess.CalledProcessError):self.verify(operator_publisher_dir=PUBLISHER)


if __name__=='__main__':unittest.main()
