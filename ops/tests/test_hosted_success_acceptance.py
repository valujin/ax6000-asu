import copy,importlib.util,unittest
from pathlib import Path
S=importlib.util.spec_from_file_location('hosted_success_acceptance',Path(__file__).parents[1]/'hosted_acceptance.py');a=importlib.util.module_from_spec(S);S.loader.exec_module(a)
class StrictRootApproval(unittest.TestCase):
 def fixture(self):
  roles={n:{'sha256':'a'*64,'size':4} for n in a.ROLES};strict={'ok':True,'acceptance_gate_relaxed':False,'normalization_performed':False,'roles':{n:{'equal':True,'before':r,'after':r} for n,r in roles.items()}};relation={'source_equal':True,'kernel_abi_equal':True,'source_patches_equal':True};difference={'full_image_equal':True,'different_bytes':0,'normalization_or_mutation_performed':False,'acceptance_gate_relaxed':False};proofs={'inspection':{'path':'/fixture','size':1,'sha256':'b'*64}};identity={'producer_commit':a.HEAD,'source_commit':a.SOURCE,'seed':a.SEED,'run_id':a.RUN};decision={'schema_version':1,'kind':a.KIND,**identity,'approved':True,'root_independently_checked_exact_proofs':True,'proofs':proofs,'required_roles':roles,'new_kernel_context_enrolled':False,'old_guards_relaxed':False,'hardware_or_SDK_compile_or_IB_smoke_claimed':False,'acceptance_basis':a.BASIS};return decision,proofs,identity,strict,relation,difference
 def test_exact_existing_context_approval_passes(self):a.verify(*self.fixture())
 def test_true_flag_without_role_proof_scope_identity_rejected(self):
  for name in ('role','proof','scope','identity','source','image'):
   d,p,i,s,r,f=copy.deepcopy(self.fixture())
   if name=='role':s['roles']['retained/Image']['after']={'sha256':'f'*64,'size':4}
   elif name=='proof':d['proofs']={}
   elif name=='scope':d['new_kernel_context_enrolled']=True
   elif name=='identity':d['run_id']=1
   elif name=='source':r['source_equal']=False
   else:f['different_bytes']=1
   with self.subTest(name=name),self.assertRaises(ValueError):a.verify(d,p,i,s,r,f)
