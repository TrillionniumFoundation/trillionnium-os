#!/usr/bin/env python3
"""Prepare exact R6 source03 publication artifacts. Never publish or dispatch."""
from pathlib import Path
import ast,base64,copy,difflib,hashlib,json,zlib

D=Path(__file__).resolve().parent
OLD=D.parent/'R5-negative-source-binding02'
C=D.parent/'R6-negative-source-candidate01'/'candidate'
B='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
BINDING=B+'/followthrough-fc33-negative-source-binding-r6-03'
DERIVED=B+'/fc33-negative-sources-native-v3-r6-03'
TRANSPORT=B+'/followthrough-fc33-negative-source-transport-r6-03'


def pin(raw):return {'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}


def enc(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()


def row(path,raw):return {'path':path,**pin(raw)}


def put(name,raw):
    path=D/name;path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():assert path.read_bytes()==raw,'refuse changed prepared artifact: '+name
    else:
        with path.open('xb') as stream:stream.write(raw)
    assert path.read_bytes()==raw


def patch(name,before,after):
    put(name,''.join(difflib.unified_diff(before.decode().splitlines(True),after.decode().splitlines(True),
        fromfile='preserved-parent',tofile='independent-R6-source03')).encode())


def assignment(raw,name,value):
    rows=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign) and len(n.targets)==1
          and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    assert len(rows)==1
    n=rows[0];before=b''.join(raw.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
    after=(name+' = '+repr(value)+'\n').encode();assert raw.count(before)==1
    return raw.replace(before,after,1),(before,after)


def mcp(value):
    return value.get('structuredContent') or json.loads(next(x['text'] for x in value['content'] if x['type']=='text'))


def main():
    compressed_old=(OLD/'transport/SOURCE-PAYLOAD.zlib').read_bytes()
    assert pin(compressed_old)=={'bytes':710094,'sha256':'6fb4b534935bd54e165245fdc090b95270a31810307ab63ee5183f40109e8964'}
    old_payload=json.loads(zlib.decompress(compressed_old));prepared={}
    for item in old_payload['files']:
        blob=old_payload['blobs'][item['sha256']]
        raw=blob['content'].encode() if blob['encoding']=='utf-8' else base64.b64decode(blob['content'],validate=True)
        assert pin(raw)=={k:item[k] for k in ('bytes','sha256')};prepared[item['path']]=raw
    assert len(prepared)==177
    parent=prepared['reference/derive_negative_sources_UNBOUND.py']
    assert pin(parent)=={'bytes':43126,'sha256':'3c64904a631b8987fa6626e2575a5e1e8046dde9ac6f6cef22273e5c86d1f982'}

    unbound=(C/'source/derive_negative_sources_UNBOUND.py').read_bytes()
    common=(C/'source/physical_fault_common.py').read_bytes()
    closure=(C/'source/negative_originals.py').read_bytes()
    sender=(C/'source/send_new_native_task_r5_fc33_r6.py').read_bytes()
    index_raw=(C/'source/REVIEWED-INPUTS.json').read_bytes()
    assert pin(unbound)=={'bytes':43869,'sha256':'12103136651db4868850352bc07fa27b7ae73f386385553128399dfd58152e57'}
    assert pin(common)=={'bytes':28166,'sha256':'32e57adc20cfc0d9de9073bbace24a328ce6409a89e0396772331900089a687b'}
    assert pin(closure)=={'bytes':44221,'sha256':'bcd391c143d8e9ff85cf4d46e0a2817a78cf316795c6dc6d871483264fc15e0c'}
    assert pin(sender)=={'bytes':41355,'sha256':'f90c6ffbf3278b22bf3a48bf055c5ca1cf43c3073c5cc7a852dd09a4cf2eab73'}
    assert pin(index_raw)=={'bytes':38297,'sha256':'9a1138f1a843814588107054057048810183f94ecb29725b46ebc40f8b560bed'}
    for name,body in [('derive_negative_sources_UNBOUND.py',unbound),('physical_fault_common.py',common),
                      ('negative_originals.py',closure),('send_new_native_task_r5_fc33_r6.py',sender),
                      ('REVIEWED-INPUTS.json',index_raw)]:put('source/'+name,body)
    put('reference/R6-CANDIDATE-DERIVATION.original.json',(C/'DERIVATION.json').read_bytes())
    for item in sorted((C/'patches').glob('*.patch')):put('r6-source-delta/'+item.name,item.read_bytes())

    release_raw=(D/'reference/release_source_DERIVATION.original.json').read_bytes()
    assert pin(release_raw)=={'bytes':9587,'sha256':'d965569c4f53d2835b442c9e2c5edc5a7a85f1fbab24a50769033dcf876954db'}
    release=json.loads(release_raw)
    assert release['state']=='SOURCE_CANDIDATES_ONLY_ACTUAL_EXECUTION_UNBOUND'
    assert release['actual_execution_slots_unbound'] is True and release['BUILD'] is False and release['READY'] is False
    actual_read=mcp(json.loads((D/'reference/release_actual_read.original.mcp.json').read_bytes()))
    observed=next(f for f in actual_read['files'] if f['sha256']==pin(release_raw)['sha256'])
    assert observed['text'].encode()==release_raw and observed['size']==len(release_raw) and observed['eof'] is True
    freeze_controller_raw=(D/'reference/runtime_freeze_controller.original.json').read_bytes()
    assert pin(freeze_controller_raw)=={'bytes':7594,'sha256':'68b5f1972b19682c57abbf3e9791feb7672ff66d81abf5c202b1f7ffc0d0b0ac'}
    controller=json.loads(freeze_controller_raw);status=mcp(controller['status']);read=mcp(controller['read'])
    assert status['exit_code']==0 and status['output_complete'] and status['output_durable'] and not status['automatic_retry']
    assert read['stdout']['eof'] and read['stderr']['eof'] and read['stderr']['bytes_hex']==''
    stdout=bytes.fromhex(read['stdout']['bytes_hex']);assert stdout==read['stdout']['text'].encode()
    frozen=json.loads(stdout)
    assert frozen['state']=='FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED'
    assert frozen['runtime_manifest']['sha256']=='270357b7649af61414d31580b3c1eaddc47174bd1bac3c8adfc02934a92c8cf5'
    assert frozen['root_chain_manifest']['sha256']=='9da8d53ebfba3e11f2406c0a59964923ff4709052fad2d5df3d2eaff8b7ec8a4'
    inputs=json.loads(prepared['SOURCE-INPUTS.json'])
    inputs.update(reference_root=BINDING+'/inputs',output_root=DERIVED,
        host_neg06_namespace='/home/alex/razr60-local-model-v150/fc33-neg06-native-v3-r6-03',
        release_source_chain={'constructor':release['constructor'],'inputs':release['source_inputs']},
        root_manifest=frozen['root_chain_manifest'])
    # Its body is unchanged b25125bc; the R6 source publisher has actually
    # materialized this current path. The real publisher will read its full body.
    inputs['materializer']['path']=B+'/followthrough-fc33-e2e-bound-source-r6-01/operator/materialize_case_r10.py'
    assert inputs['materializer']['bytes']==24834 and inputs['materializer']['sha256']=='b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290'
    inputs_raw=enc(inputs);input_descriptor=row(BINDING+'/SOURCE-INPUTS.json',inputs_raw)
    before=b'FROZEN_INPUTS = None';after=('FROZEN_INPUTS = '+repr(input_descriptor)).encode()
    assert unbound.count(before)==1
    bound=unbound.replace(before,after,1);assert bound.replace(after,before,1)==unbound
    compile(bound,'<unexecuted-R6-source03-constructor>','exec')
    put('source/derive_negative_sources_BOUND.py',bound);put('SOURCE-INPUTS.json',inputs_raw)
    patch('SOURCE.patch',unbound,bound)

    proof=json.loads(prepared['BINDING-PROOF.json'])
    proof.update(constructor_parent=pin(unbound),constructor=row(BINDING+'/source/derive_negative_sources_BOUND.py',bound),
        source_inputs=input_descriptor,binding_output=BINDING,derived_output=DERIVED,
        reference_index=row(BINDING+'/inputs/REVIEWED-INPUTS.json',index_raw),
        reference_count=172,
        reference_bytes=sum(r['bytes'] for r in json.loads(index_raw)['files']),
        existing_actual_inputs={k:inputs[k] for k in ('release_source_chain','root_manifest','actual_policy','policy_adoption','materializer')},
        new_owned_input_copies_not_yet_published=BINDING,new_source_output_not_yet_published=DERIVED,
        host_neg06_namespace_is_only_a_future_output_literal_not_an_execution=inputs['host_neg06_namespace'],
        actual_runtime_source_freeze=release['runtime_freeze_authority'],
        actual_release_source_derivation={'path':observed['path'],**pin(release_raw)},
        actual_release_source_binding=release['source_binding'],
        original_production15_unchanged=True,runtime38_exact_reviewed_R6_source=True,
        business_sender=row(B+'/send_new_native_task_r5_fc33_r6.py',sender),
        reviewed_empty_original_reader_control={'source':pin((D/'reference/source_reader.candidate.py').read_bytes()),
            'scope':'Existing actual4/4 reader/constructor controls; no new R6 execution or qualification asserted.'},
        previous_source02_publication={'job_id':'1a1b27082de-fc05-7e06','exit_code':1,
            'binding_root':old_payload['binding_root'],'derived_root':old_payload['derived_root'],
            'reason':'bounded typed source descriptor rejected one of three exact empty adoption originals',
            'original_failure_and_existing_namespace_retained':True,'no_in_place_retry_or_overwrite':True})
    proof.pop('original_production15_and_runtime38_unchanged',None)
    assert proof['complete_constructor_inverse'] is True and proof['source_constructor_positive_executed'] is False
    assert all(proof[k] is None for k in ('actual_BUILD','actual_READY','actual_case_plans','new_native_scope','new_nonce'))
    proof_raw=enc(proof);put('BINDING-PROOF.json',proof_raw)
    prepared.update({'source/derive_negative_sources_BOUND.py':bound,
        'reference/derive_negative_sources_UNBOUND.py':unbound,'SOURCE-INPUTS.json':inputs_raw,
        'SOURCE.patch':(D/'SOURCE.patch').read_bytes(),'BINDING-PROOF.json':proof_raw,
        'inputs/REVIEWED-INPUTS.json':index_raw,
        'inputs/candidate/templates/physical-fault/physical_fault_common.py':common,
        'inputs/candidate/templates/closure/negative_originals.py':closure,
        'inputs/candidate/templates/sender/send_new_native_task_r5_fc33_r6.py':sender})
    index=json.loads(index_raw);assert len(index['files'])==172
    for item in index['files']:assert pin(prepared['inputs/'+item['path']])=={k:item[k] for k in ('bytes','sha256')}
    assert len(prepared)==178
    blobs={};members=[]
    for name,raw in sorted(prepared.items()):
        digest=pin(raw)['sha256']
        try:blob={'encoding':'utf-8','content':raw.decode('utf-8')}
        except UnicodeDecodeError:blob={'encoding':'base64','content':base64.b64encode(raw).decode()}
        blobs.setdefault(digest,blob);members.append({'path':name,**pin(raw)})
    payload={'schema':old_payload['schema'],'binding_root':BINDING,'derived_root':DERIVED,'files':members,'blobs':blobs}
    payload_raw=(json.dumps(payload,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
    compressed=zlib.compress(payload_raw,9);put('transport/SOURCE-PAYLOAD.zlib',compressed)
    payload_descriptor=row(TRANSPORT+'/SOURCE-PAYLOAD.zlib',compressed)
    put('transport/PAYLOAD-MANIFEST.json',enc({'schema':'hepta.fc33.negative-source-publication-payload-manifest.v1',
        'payload':payload_descriptor,'raw_payload':pin(payload_raw),'files':members,'file_count':178,
        'all172_reference_bytes_verified':True,'input_publication_executed':False,'source_derivation_executed':False}))

    publisher_parent=(D/'reference/publish_negative_sources_r5_02.original.py').read_bytes()
    assert pin(publisher_parent)=={'bytes':19652,'sha256':'b1ae10610b16aeb4620ec6f66362d3945e1f2a40717465303b24724e03b4eb81'}
    publisher=publisher_parent;edits=[]
    for name,value in [('SOURCE_PAYLOAD',payload_descriptor),('PAYLOAD_RAW',pin(payload_raw)),
        ('EXPECTED_INPUTS',input_descriptor),('EXISTING_SOURCE_BINDING',release['source_binding']),
        ('SOURCE_PARENT',pin(unbound)),('REFERENCE_INDEX',pin(index_raw))]:
        publisher,edit=assignment(publisher,name,value);edits.append(edit)
    for before,after in [(b"binding_root.name == 'followthrough-fc33-negative-source-binding-r5-02'",b"binding_root.name == 'followthrough-fc33-negative-source-binding-r6-03'"),
        (b"derived_root.name == 'fc33-negative-sources-native-v3-r5-02'",b"derived_root.name == 'fc33-negative-sources-native-v3-r6-03'"),
        (b"len(value['files']) == 177",b"len(value['files']) == 178"),
        (b"len(value['blobs']) <= 177",b"len(value['blobs']) <= 178"),
        (b"len({row['path'] for row in index['files']}) == 171",b"len({row['path'] for row in index['files']}) == 172"),
        (b"'all 171 reviewed sources must be retained'",b"'all 172 reviewed sources must be retained'"),
        (b"'reference_sources': 171",b"'reference_sources': 172")]:
        assert publisher.count(before)==1;publisher=publisher.replace(before,after,1);edits.append((before,after))
    n=next(n for n in ast.parse(publisher).body if isinstance(n,ast.FunctionDef) and n.name=='source_reader')
    before=b''.join(publisher.splitlines(keepends=True)[n.lineno-1:n.end_lineno])
    after=(D/'reference/source_reader.candidate.py').read_bytes()
    assert pin(after)=={'bytes':1345,'sha256':'ecd6139f9161bc18d59eee16bd58f3f3de478f39643e3967d12c84167ad753c8'}
    assert publisher.count(before)==1;publisher=publisher.replace(before,after,1);edits.append((before,after))
    inverse=publisher
    for before,after in reversed(edits):
        assert inverse.count(after)==1;inverse=inverse.replace(after,before,1)
    assert inverse==publisher_parent
    compile(publisher,'<unexecuted-R6-source03-publisher>','exec')
    put('transport/publish_negative_sources_once.py',publisher);patch('PUBLISHER.patch',publisher_parent,publisher)
    put('PUBLISHER-DERIVATION.json',enc({'schema':'hepta.fc33.negative-R6-source03-publisher-derivation.v1',
        'parent':pin(publisher_parent),'candidate':pin(publisher),'complete_inverse':True,
        'changed_constant_assignments':['SOURCE_PAYLOAD','PAYLOAD_RAW','EXPECTED_INPUTS','EXISTING_SOURCE_BINDING','SOURCE_PARENT','REFERENCE_INDEX'],
        'changed_literal_namespaces':[BINDING,DERIVED],'prepared_member_count':178,'reviewed_reference_count':172,
        'source_reader_only_change':'exact existing read() envelope 0<bytes<=1MiB to0<=bytes<=16MiB; full9/SHA/singlelink/book unchanged',
        'already_controlled_source_reader':pin((D/'reference/source_reader.candidate.py').read_bytes()),'all_remaining_publisher_bytes_identical':True,
        'actual_execution':None,'phone_calls':0,'production15_source_changes':0}))
    script=row(TRANSPORT+'/publish_negative_sources_once.py',publisher)
    request={'host':'mac','executable':'/usr/bin/python3',
        'args':['-I','-B',script['path'],'--publish-negative-source-candidate-once',script['sha256']],
        'idempotency_key':'fc33-negative-source-only-native-v3-r6-03','timeout_seconds':120}
    put('PROCESS-REQUEST.UNEXECUTED.json',enc(request))
    chunks=[]
    for offset in range(0,len(compressed),65536):
        raw=compressed[offset:offset+65536];name='chunks/source-payload-%03d.bin'%len(chunks)
        put('transport/'+name,raw);chunks.append({'local_relative_path':name,'offset':offset,**pin(raw)})
    put('TRANSPORT-PLAN.UNEXECUTED.json',enc({'schema':'hepta.fc33.negative-source-only-unexecuted-transport.v1',
        'state':'PREPARED_R6_SOURCE03_FOR_ROOT_REVIEW_NOT_TRANSPORTED_OR_EXECUTED',
        'new_owned_transport_root':TRANSPORT,'required_existing_staged_files_before_the_one_process_request':[script,payload_descriptor],
        'source_payload_chunks':chunks,'request':row(str(D/'PROCESS-REQUEST.UNEXECUTED.json'),enc(request)),
        'old_failed_source01_and02_namespaces_unchanged':True,'no_delete_or_automatic_retry':True,
        'actual_process':None,'actual_source_outputs':None,'actual_BUILD':None,'actual_READY':None,
        'actual_case_plans':None,'phone_calls':0,'native_dispatches':0,'model_requests':0}))
    direct=[inputs['release_source_chain'][k] for k in ('constructor','inputs')]
    direct +=[inputs[k] for k in ('root_manifest','actual_policy','policy_adoption','materializer')]
    direct +=[release['source_binding'],row(B+'/send_new_native_task_r5_fc33_r6.py',sender)]
    parent_dirs={str(p) for name in prepared for p in Path(name).parents if str(p)!='.'}
    bounds={'schema':'hepta.fc33.negative-R6-source03-exact-byte-envelopes.v1',
        'individual_source_original_minimum':0,'individual_source_original_maximum':16777216,
        'negative_constructor_total_limit':67108864,'published_tree_maximum':33554432,
        'prepared_raw_payload_limit':8388608,'prepared_member_individual_limit':4194304,
        'prepared_member_maximum_count':256,'prepared_directory_maximum_count':128,
        'prepared_payload_members':{'count':len(members),'bytes':sum(r['bytes'] for r in members),
            'maximum':max(members,key=lambda r:r['bytes']),'all_file_pins':members},
        'prepared_directory_count_including_root':1+len(parent_dirs),
        'reference_sources':{'count':172,'bytes':sum(r['bytes'] for r in index['files'])},
        'prepared_compressed_payload':pin(compressed),'prepared_raw_payload':pin(payload_raw),
        'direct_existing_source_inputs':direct,'direct_existing_source_input_bytes':sum(r['bytes'] for r in direct),
        'actual_transitive_full9_and_total_bytes':None,
        'transitive_count_will_be_observed_only_by_actual_constructor':True,
        'final_tree_bounds_rechecked_after_proof_and_terminal_additions':True,
        'phone_actor_output_and_image_budgets_unchanged':True}
    assert len(members)<=256 and bounds['prepared_payload_members']['bytes']<=33554432
    assert len(parent_dirs)<=128 and len(payload_raw)<=8388608 and all(r['bytes']<=4194304 for r in members)
    put('BYTE-BOUNDS.json',enc(bounds))
    put('NEG03-PROTOCOL-BOUNDARY.json',(OLD/'NEG03-PROTOCOL-BOUNDARY.json').read_bytes())
    print(json.dumps({'output':str(D),'constructor_unbound':pin(unbound),'constructor_bound':pin(bound),
        'source_inputs':pin(inputs_raw),'publisher':pin(publisher),'payload':pin(compressed),
        'payload_raw':pin(payload_raw),'prepared_files':len(members),'prepared_file_bytes':sum(r['bytes'] for r in members),
        'request':pin(enc(request)),'actual_execution':None,'phone_calls':0},sort_keys=True))


if __name__=='__main__':main()
