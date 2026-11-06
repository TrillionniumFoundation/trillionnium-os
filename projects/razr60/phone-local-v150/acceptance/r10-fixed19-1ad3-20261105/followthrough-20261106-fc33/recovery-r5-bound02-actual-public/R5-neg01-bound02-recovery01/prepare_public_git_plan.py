"""Exact public allowlist only. No private packet/XML/draft or Git ref writes."""
from pathlib import Path
import hashlib,json
ROOT=Path(__file__).resolve().parent.parent
ALLOW={
'R5-neg01-bound02-failure':[
 'SENDER-PUBLIC-OBSERVATION.original.json','inspect_sender_originals_host.py'],
'R5-neg01-bound02-probe01':[
 'DISPATCH.json','EXACT-TARGETS-TRANSPORT.original.json','EXACT-TARGETS.PUBLIC.original.json',
 'HOST-DERIVATION.json','HOST-ORIGINALS-MANIFEST.json','HOST-PREPARE-BINDING.json',
 'HOST-PREPARE-CONTROLLER.public.json','HOST-IMPORT-CONTROLLER.original.json',
 'HOST-RECEIVER-DERIVATION.json','HOST-VERIFICATION.PUBLIC.original.json','INPUTS.json','MANIFEST.json',
 'PHONE-COMMAND.sh','PHONE-REQUEST.json','ROOT-DISPATCH-RUNNER.py',
 'ROOT-READONLY-DISPATCH-CONTROLLER.original.json','ROOT-READONLY-DISPATCH-START.original.json',
 'SENDER-TERMINAL-PROOF.json','SENDER-TERMINAL-PROOF.local.json','SOURCE-DERIVATION.json','SOURCE.py',
 'build_host_input_job.py','build_host_input_job.discovery-parent.py','build_probe.py','build_receiver.py',
 'prepare_inputs_host.template.py','probe_extension.py','receiver_extension.py','verify_probe_result_host.py',
 'inputs/LEASE.original.json','inputs/PREPARED.original.json','inputs/ROOT-FAILURE.original.json',
 'inputs/ROOT-PLAN.original.json','inputs/RUNTIME-MANIFEST.original.json','inputs/SENDER-CONTRACT.original.json',
 'inputs/SENDER-RESULT.original.json','inputs/STAGE-COMPLETE.original.json','inputs/phone-stage.stdout.original',
 'inputs/phone_once.original.py','inputs/sender-execute.CHILD.json','inputs/sender-execute.INTENT.json',
 'inputs/sender-execute.OUTPUT-CAPTURE.json'],
'R5-neg01-bound02-recovery01':[
 'AUTHORITY.json','DISPATCH.json','HOST-CONTROLS.json','HOST-GUARD-BINDING.json','HOST-PRE-DISPATCH.py',
 'HOST-PREVIEW-REQUEST.json','MANIFEST.json','PHONE-COMMAND.sh','PHONE-REQUEST.json',
 'ROOT-ACTUAL-DISPATCH-CONTROLLER.original.json','ROOT-ACTUAL-DISPATCH-START.original.json',
 'ROOT-ACTUAL-RESULT-INFO.original.mcp.json','ROOT-HOST-PREVIEW-CONTROLLER.original.json',
 'ROOT-HOST-PREVIEW-START.original.json','ROOT-REQUEST-PUBLICATION.original.mcp.json','ROOT-SOURCE-REVIEW.json',
 'SOURCE.py','TARGETS.original.json','build_host_guard.py','build_recovery.py','host_guard_extension.py',
 'recovery_extension.py','prepare_public_git_plan.py']}
EXCLUDED=[
 'R5-neg01-bound02-probe01/PRIVATE-HOST-CONTROLLERS.original.json',
 'R5-neg01-bound02-probe01/prepare_inputs_host_BOUND.py']
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
rows=[]
for directory,names in ALLOW.items():
 for name in names:
  relative=directory+'/'+name;p=ROOT/relative
  assert str(p.resolve())==str(p) and p.is_file() and not p.is_symlink()
  b=p.read_bytes();b.decode('utf-8')
  assert not any(x in relative for x in ('PRIVATE','packet.original','ORIGINALS.PRIVATE','USER-DRAFT','PRESERVED-USER-DRAFT'))
  rows.append({'path':relative,'local_path':str(p),'bytes':len(b),'sha256':sha(b),'git_blob_sha':hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),'mode':'100644','type':'blob'})
assert len(rows)==len({r['path'] for r in rows})
excluded=[]
for name in EXCLUDED:
 p=ROOT/name;b=p.read_bytes();excluded.append({'path':name,'bytes':len(b),'sha256':sha(b),'reason':'complete private host original package or its source payload; retained privately, never uploaded'})
plan={'schema':'hepta.fc33.bound02.public-git-upload-plan.v1','repository_full_name':'TrillionniumFoundation/trillionnium-os','state':'EXACT_PUBLIC_ALLOWLIST_ONLY_ACTUAL_UPLOAD_REQUIRED','files':rows,'file_count':len(rows),'unique_content_count':len({r['git_blob_sha'] for r in rows}),'excluded_private_files':excluded,'excluded_private_namespaces':['all P4 readonly packet.original.json and original XML/request/draft byte blobs','all private sender archives and raw source sender JSON/XML bodies'],'public_fields_only':'source code, finite expected paths, full SHA/metadata observations, exact controller records without private source stdin, and original negative/failed evidence','cleanup_independent_closure':'pending independent receiver; no premature closed status','tree_or_ref_write_authorized_by_this_plan':False,'phone_calls':0}
out=ROOT/'R5-neg01-bound02-recovery01/PUBLIC-GIT-UPLOAD-PLAN.json';out.write_bytes(enc(plan));print(json.dumps({'plan':str(out),'bytes':len(enc(plan)),'sha256':sha(enc(plan)),'files':len(rows),'unique_blobs':plan['unique_content_count']},sort_keys=True))
