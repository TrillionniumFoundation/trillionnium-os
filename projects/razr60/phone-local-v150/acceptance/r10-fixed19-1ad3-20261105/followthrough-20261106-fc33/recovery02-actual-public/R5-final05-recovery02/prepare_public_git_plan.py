#!/usr/bin/env python3
"""Exact public whitelist only. Computes expected IDs; does not claim upload."""
from pathlib import Path
import base64,gzip,hashlib,json
R=Path(__file__).resolve().parent.parent
OBS='R5-final05-parent-reconcile-probe02'
REC='R5-final05-recovery02'
def sha(b):return hashlib.sha256(b).hexdigest()
names={
OBS:[
 'ACTUAL-CONTRACT-INSPECTION.original.json','ACTUAL-CONTRACT-INSPECTION.stdout.original.json',
 'FAILURE-PARENT-PROFILE-REFERENCE.original.json','FAILURE-PARENT-REFERENCE.gzip.base64','FAILURE-REFERENCE-CONTROLLER-ORIGINALS.json',
 'HOST-IMPORT-CONTROLLER-ORIGINALS.json','HOST-IMPORTER-ACTUAL-CONTRACT-CHECK.json',
 'HOST-IMPORTER-V2.patch','HOST-IMPORTER-V3.patch','HOST-IMPORTER-V4.patch',
 'HOST-VERIFICATION-PUBLIC.binary-transport.json','HOST-VERIFICATION.PUBLIC.original.json',
 'INPUTS.json','MANIFEST.json','PHONE-COMMAND.sh','PHONE-REQUEST.json',
 'ROOT-HOST-VERIFICATION.PUBLIC.original.json','ROOT-HOST-VERIFICATION.raw.base64','SOURCE.py',
 'build_observer.py','build_observer02.py','observer_extension.py','verify_observer_host.py',
 'import_parent_observer_host.py','import_parent_observer_host_v2.py','import_parent_observer_host_v3.py','import_parent_observer_host_v4.py',
 'candidate02/HOST-CONTROLS.json','candidate02/INPUTS.json','candidate02/MANIFEST.json',
 'candidate02/PHONE-COMMAND.sh','candidate02/PHONE-REQUEST.json','candidate02/ROOT-ACTUAL-CONTROLLER.original.json','candidate02/SOURCE.py'],
REC:[
 'HOST-READER02-BINDING.json','HOST-READER02-DERIVATION.json','HOST-READER02.patch',
 'HOST-VERIFICATION.PUBLIC.original.json','ROOT-HOST-IMPORT-CONTROLLER.original.json','ROOT-HOST-VERIFICATION-READ.original.mcp.json',
 'PUBLIC-PACKAGE-OUTCOME.json','build_host_guard02.py','build_recovery02.py','check_recovery02_host.py',
 'host_guard_reconciliation_extension.py','reconciliation_extension.py','verify_recovery02_result_BOUND.py','verify_recovery02_result_UNBOUND.py',
 'candidate01/AUTHORITY.json','candidate01/DERIVED-TARGETS.EXPECTATION-ONLY.json','candidate01/EXTENSION.patch','candidate01/FINAL-DELIVERY.json',
 'candidate01/HOST-CONTROLS.json','candidate01/HOST-GUARD-DERIVATION.json','candidate01/HOST-GUARD-EXTENSION.py','candidate01/HOST-GUARD.patch',
 'candidate01/HOST-PRE-DISPATCH.py','candidate01/MANIFEST.json','candidate01/MANIFEST.pre-metadata-fix.original.json',
 'candidate01/PHONE-COMMAND.sh','candidate01/PHONE-REQUEST.json','candidate01/RECONCILIATION.original.json',
 'candidate01/ROOT-ACTUAL-EXECUTION-CONTROLLER.original.json','candidate01/ROOT-EXECUTION-DECISION.json','candidate01/ROOT-HOST-PREVIEW-CONTROLLER.original.json',
 'candidate01/SOURCE-COMPRESSION.json','candidate01/SOURCE.py','candidate01/reconciliation_extension.py','candidate01/recovery_extension.py']}
standalone=['R5-final05-parent-observer-independent-review.json','R5-final05-recovery02-independent-complete-source-review.json',
 'R5-final05-recovery02-independent-host-guard-review.json','R5-final05-recovery02-independent-interface-review.json']
paths=[k+'/'+p for k,group in names.items() for p in group]+standalone
assert len(paths)==len(set(paths))
expected_public='3f07757cf054f697e2a81ad1ce0752c6e1aa5ca6a7b09488cb122363b76b038a'
for name in ['HOST-VERIFICATION.PUBLIC.original.json','ROOT-HOST-VERIFICATION.PUBLIC.original.json']:
 assert sha((R/OBS/name).read_bytes())==expected_public
assert sha(base64.b64decode((R/OBS/'ROOT-HOST-VERIFICATION.raw.base64').read_bytes(),validate=False))==expected_public
assert sha(gzip.decompress(base64.b64decode((R/OBS/'FAILURE-PARENT-REFERENCE.gzip.base64').read_bytes(),validate=False)))=='5dd20c0bb2fbc049dea1b168cb83a730a3abc9916677be5e47ac81bbd7518427'
binary=json.loads((R/OBS/'HOST-VERIFICATION-PUBLIC.binary-transport.json').read_bytes())
assert sha(b''.join(base64.b64decode(c['data_base64'],validate=True) for c in binary['chunks']))==expected_public
rows=[]
for relative in paths:
 p=R/relative;raw=p.read_bytes();raw.decode('utf-8')
 assert p.is_file() and not p.is_symlink()
 assert '/private/' not in relative and 'packet.original' not in relative and not relative.endswith('.xml')
 rows.append({'path':relative,'local_path':str(p),'bytes':len(raw),'sha256':sha(raw),
              'expected_git_blob_sha1':hashlib.sha1(b'blob '+str(len(raw)).encode()+b'\0'+raw).hexdigest(),
              'content_class':'reviewed source, public metadata, public receipt or failure correction','mode':'100644'})
plan={'schema':'hepta.fc33.final05.exact-public-git-upload-plan.v1','repository':'TrillionniumFoundation/trillionnium-os',
      'state':'EXPECTED_IDENTIFIERS_ONLY_NOT_UPLOAD_RECEIPTS','files':rows,'file_count':len(rows),'total_bytes':sum(r['bytes'] for r in rows),
      'distinct_git_blobs':len({r['expected_git_blob_sha1'] for r in rows}),
      'private_phone_results_packets_XML_foreign_bodies_excluded':True,'complete_controller_failures_and_revisions_retained':True,
      'source_only_preparation_artifacts_keep_original_unexecuted_or_unbound_state':True,
      'phone_calls':0,'tree_commit_or_ref_updated':False}
raw=(json.dumps(plan,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
p=R/REC/'PUBLIC-GIT-UPLOAD-PLAN.json'
if p.exists():assert p.read_bytes()==raw
else:p.write_bytes(raw)
print(json.dumps({'path':str(p),'bytes':len(raw),'sha256':sha(raw),'files':len(rows),'unique_blobs':plan['distinct_git_blobs'],'total_bytes':plan['total_bytes']},sort_keys=True))
