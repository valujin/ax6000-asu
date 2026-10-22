"""Finite successful LATEST existing-context approval; no source proxy or bypass."""
HEAD='deeea41a13b8e3ffff64fce6deec6f37d5085b12';SOURCE='a99b0888b88f134f56bcb2a7d93027b5d20638a9';SEED='7578632e519ac983062468679ea9f7f52c8a4466ef2685dafafe56961801c4a5';RUN=39691822857
KIND='ax6000-latest-accepted-existing-context-root-decision-v1';BASIS='all-ten-prior-context-roles-source-ABI-patches-and-complete-functional-Image-byte-identical';ROLES={'.config','.config.set','.vermagic','Module.symvers','include/config/kernel.release','include/generated/autoconf.h','modules.builtin.modinfo','retained/.config','retained/Module.symvers','retained/Image'}
DECISION_SHA='4ba65dc1f31383a40f538ddc5c1c6ad29dc5ba12c7885771b04d9d5ac303a1e9';INSPECTION_SHA='46cf44d7d9d56d69c9d35c53228430a594a53f02dfaab95c8ae22771ce7a9a6a';CAPTURE_SHA='f576dca2c57f36b9048a7dc5da27da46e63ce1abe308b6441cf2f2ed9f0345ae'
def need(ok,message):
 if not ok:raise ValueError(message)
def verify(decision,proofs,identity,strict,relation,difference):
 need(decision.get('schema_version')==1 and decision.get('kind')==KIND and all(decision.get(k)==v for k,v in identity.items()) and decision.get('approved') is True and decision.get('root_independently_checked_exact_proofs') is True,'Root existing-context identity/approval differs')
 need(decision.get('proofs')==proofs and set(strict.get('roles',{}))==ROLES and strict.get('ok') is True and strict.get('acceptance_gate_relaxed') is False and strict.get('normalization_performed') is False,'Exact strict proof roles required')
 roles={}
 for name,row in strict['roles'].items():
  need(row.get('equal') is True and row.get('before')==row.get('after'),'Prior whole context differs: '+name);roles[name]=row['after']
 need(decision.get('required_roles')==roles and decision.get('new_kernel_context_enrolled') is False and decision.get('old_guards_relaxed') is False and decision.get('hardware_or_SDK_compile_or_IB_smoke_claimed') is False and decision.get('acceptance_basis')==BASIS,'Root decision context/scope differs')
 need(set(relation)=={'source_equal','kernel_abi_equal','source_patches_equal'} and all(v is True for v in relation.values()),'Prior source/ABI/source-patches differ')
 need(difference.get('full_image_equal') is True and type(difference.get('different_bytes')) is int and difference['different_bytes']==0 and difference.get('normalization_or_mutation_performed') is False and difference.get('acceptance_gate_relaxed') is False,'Complete prior functional Image must remain identical')
 return roles
