#!/usr/bin/env python3
"""Bind existing post evidence sources to actual originals without remote execution.

The three phases prepare a collector, a mirror, or the native adoption-input
collection plan. Source preparation changes exactly one previously-None literal.
No remote process, parser, policy setter, or adoption entry is invoked here.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import stat

B = Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
P = Path('/home/alex/razr60-local-model-v150/policy-runtime-properties-r10-r1')
LIVE = B/'policy-runtime-properties-r10-live-02'
COLLECTOR_ROOT = P/'post-live-root02-independent-evidence-source01'
EVIDENCE = P/'post-live-root02-independent-evidence01'
ACTUAL = P/'post-live-root02-actual01'
MIRROR_OUT = B/'policy-runtime-properties-r10-post-live-root02-independent-proof01'
INDEPENDENT_ROOT = B/'policy-runtime-properties-r10-independent-host-verifier-r1-candidate01'
COLLECTOR_PIN = {'bytes':19671,'sha256':'7f6c064c4288b912c090ee3491792e911b2c3af3443a6b4b91d27b77e1349200'}
MIRROR_PIN = {'bytes':19991,'sha256':'e2ba3f8e942e5543e252a2782d66ab528da40c9c23a7d9f70a04381dd0980af8'}
APPLIED_PIN = {'bytes':124306,'sha256':'5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00'}
INDEPENDENT_PIN = {'bytes':126796,'sha256':'74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152'}
LIVE_PIN = {'bytes':22659,'sha256':'01be4b34e7bcbb5a32aa47a249e36afbba94e30a6275b444f5143f2c8396e7f1'}
INDEPENDENT_MANIFEST_PIN = {'bytes':6924,'sha256':'1b4b515646c4ba6936633b727895eca7a21afb69d28914fdc66213c5411344c7'}
OFFLINE_PIN = {'bytes':204360,'sha256':'efb2e2bfc17182f79db6036c4fddb9e06cf16d73e500766a7d8076e243a12390'}
PARENT_PIN = {'bytes':2667608,'sha256':'50f07eccca1a1afd59fac1c31f4d40a26e5396635c6516e695694a8923fd3ea7'}
ACTUAL_POLICY_PIN = {'bytes':2667740,'sha256':'f8219f9c3ad2e1d16a95fda8d5f0bc7612a31e00c0a661e53bf9a6e921c49d70'}
POST_PIN = {'bytes':65251,'sha256':'85f325f9525c3470b2fbfe1bf7167f80a54febcffd87d08d2e6cbcdde4597471'}
RUNNER_PIN = {'bytes':9767,'sha256':'0793b960f8aed79421097cc8be5ab465ce49a080af1231fbcd9b51e6a4209d6e'}
SCHEMA = 'hepta.runtime-properties-r10.post-evidence-binding-inputs.v1'
META = ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
HASH = re.compile('[0-9a-f]{64}\\Z')


def need(ok, message):
    if not ok:
        raise ValueError(message)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def enc(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode()


def strict(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            need(key not in result, 'duplicate JSON key')
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def bp(row):
    return {key:row[key] for key in ('bytes','sha256')}


def desc(path, raw):
    return {'path':str(path),'bytes':len(raw),'sha256':sha(raw)}


def exact3(row, maximum=64*1024*1024):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}, 'exact three-field descriptor')
    need(type(row['path']) is str, 'original path string')
    path = Path(row['path'])
    need(path.is_absolute() and str(path)==row['path'] and '..' not in path.parts and '\0' not in row['path'],
        'canonical absolute original path')
    need(type(row['bytes']) is int and 0<=row['bytes']<=maximum
        and type(row['sha256']) is str and HASH.fullmatch(row['sha256']), 'bounded original byte pin')
    return row


class Originals:
    def __init__(self):
        self.seen = {}

    def read(self, row):
        exact3(row)
        path = Path(row['path'])
        need(path.resolve(strict=True)==path, 'canonical existing local original')
        fd = os.open(path, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            before = os.fstat(fd)
            need(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==row['bytes'],
                'regular single-link exact-sized local original')
            with os.fdopen(fd, 'rb', closefd=False) as stream:
                raw = stream.read(before.st_size+1)
            metadata = [getattr(before, key) for key in META]
            need(metadata==[getattr(os.fstat(fd), key) for key in META]
                ==[getattr(path.lstat(), key) for key in META]
                and desc(path, raw)==row, 'local original changed or differs')
        finally:
            os.close(fd)
        observed = {'descriptor':dict(row),'metadata':metadata}
        previous = self.seen.get(str(path))
        need(previous is None or previous==observed, 'local original changed across reads')
        self.seen[str(path)] = observed
        return raw

    def recheck(self):
        for item in list(self.seen.values()):
            self.read(item['descriptor'])


def single_literal(raw, name, value):
    tree = ast.parse(raw)
    matches = [node for node in tree.body if isinstance(node, ast.Assign)
        and len(node.targets)==1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id==name]
    need(len(matches)==1 and isinstance(matches[0].value, ast.Constant)
        and matches[0].value.value is None, 'exact single unpublished literal required')
    node = matches[0].value
    lines = raw.splitlines(keepends=True)
    start = sum(map(len, lines[:node.lineno-1]))+node.col_offset
    end = sum(map(len, lines[:node.end_lineno-1]))+node.end_col_offset
    literal = repr(value).encode('utf-8')
    need(ast.literal_eval(literal.decode())==value, 'literal roundtrip')
    bound = raw[:start]+literal+raw[end:]
    need(bound[:start]+raw[start:end]+bound[start+len(literal):]==raw, 'whole-source literal inverse')
    revised = ast.parse(bound)
    revised_node = next(node for node in revised.body if isinstance(node, ast.Assign)
        and len(node.targets)==1 and isinstance(node.targets[0], ast.Name) and node.targets[0].id==name)
    revised_node.value = ast.Constant(value=None)
    need(ast.dump(tree, include_attributes=False)==ast.dump(revised, include_attributes=False),
        'only the allowed literal RHS may change')
    return bound


def live_originals(o):
    row = {'path':str(LIVE/'LIVE-PROVENANCE-INPUTS.json'),**LIVE_PIN}
    live = strict(o.read(row))
    need(live['schema']=='hepta.runtime-properties-r10.live-provenance-inputs.v2', 'exact actual v2 live provenance')
    applied = live['originals']['policy_runtime_properties_verifier.original.py']
    independent = live['independent_verifier_source']
    need(applied=={'path':str(LIVE/'capture/originals/policy_runtime_properties_verifier.original.py'),**APPLIED_PIN}
        and independent=={'path':str(INDEPENDENT_ROOT/'source/policy_runtime_properties_verifier.py'),**INDEPENDENT_PIN},
        'separate exact actual and independent verifier originals')
    o.read(applied);o.read(independent)
    need(bp(live['originals']['live-policy-after.bin'])==ACTUAL_POLICY_PIN, 'actual exported policy identity')
    return row, live


def completed_post(report, execution, report_row, execution_row):
    exact3(report_row);exact3(execution_row)
    need(report_row['path']==str(ACTUAL/'comparison/RESULT.json')
        and execution_row['path']==str(ACTUAL/'EXECUTION.RESULT.json'), 'fixed actual post namespace')
    need(report['schema']=='hepta.runtime-properties-r10.complete-policy-comparison.v1'
        and report['state']=='EXACT_APPROVED_RUNTIME_PROPERTY_READ_DELTA_VERIFIED'
        and report['comparison_kind']=='post_live_export'
        and type(report['checks']) is list and len(report['checks'])==16
        and type(report['check_count']) is int and type(report['passed_count']) is int
        and report['check_count']==report['passed_count']==16
        and all(row['passed'] is True for row in report['checks'])
        and bp(report['parent'])==PARENT_PIN and bp(report['candidate'])==ACTUAL_POLICY_PIN
        and bp(report['sources']['comparator'])==POST_PIN, 'actual completed post16 report')
    need(execution['schema']=='hepta.runtime-properties.actual-host-execution.v1'
        and execution['state']=='ACTUAL_HOST_POST_LIVE_COMPLETE_COMPARISON_FINISHED'
        and type(execution['returncode']) is int and execution['returncode']==0
        and execution['timed_out'] is False and execution['captured_streams_complete'] is True
        and execution['all_originals_rechecked'] is True and execution['automatic_retry'] is False
        and execution['check_count']==execution['passed_count']==16
        and bp(execution['source'])==RUNNER_PIN and execution['report']==report_row
        and execution['parent']==report['parent'] and execution['candidate']==report['candidate'],
        'actual independent post outer terminal')


def collector(o, request, out):
    need(set(request)=={'schema','phase','template','report_copy','execution_copy',
        'controller_status_copy','controller_read_copy'}, 'exact collector binding input fields')
    template = o.read(request['template'])
    need(bp(request['template'])==COLLECTOR_PIN, 'reviewed independent collector template')
    status_raw = o.read(request['controller_status_copy']);read_raw = o.read(request['controller_read_copy'])
    status = strict(status_raw);read = strict(read_raw)
    job = status['job_id']
    need(type(job) is str and 1<=len(job)<=80 and read['job_id']==job
        and status['state']=='succeeded' and type(status['exit_code']) is int and status['exit_code']==0
        and status['output_complete'] is True and status['output_durable'] is True
        and status['timed_out'] is False, 'authoritative same-job original controller terminal')
    stdout = read['stdout'];stderr = read['stderr']
    need(type(stdout['text']) is str and type(stderr['text']) is str, 'controller raw text types')
    summary_raw = stdout['text'].encode('utf-8')
    need(stdout['offset']==0 and stdout['eof'] is True
        and stdout['next_offset']==stdout['size']==len(summary_raw)
        ==status['log_bytes']['stdout']['stored']==status['log_bytes']['stdout']['seen']
        and bytes.fromhex(stdout['bytes_hex'])==summary_raw
        and stderr['offset']==stderr['next_offset']==stderr['size']==0 and stderr['eof'] is True
        and stderr['text']==stderr['bytes_hex']==''
        and status['log_bytes']['stderr']['seen']==status['log_bytes']['stderr']['stored']==0,
        'complete lossless controller stdout and empty stderr originals')
    summary = strict(summary_raw)
    need(summary['state']=='ACTUAL_HOST_POST_LIVE_COMPLETE' and type(summary['checks']) is int
        and summary['checks']==16, 'native post runner controller stdout required')
    report_row = exact3(summary['report']);execution_row = exact3(summary['execution'])
    need(bp(request['report_copy'])==bp(report_row) and bp(request['execution_copy'])==bp(execution_row),
        'local mirrors must match actual controller-named originals')
    report = strict(o.read(request['report_copy']));execution = strict(o.read(request['execution_copy']))
    completed_post(report, execution, report_row, execution_row)
    need(summary['candidate']==report['candidate'], 'controller actual exported policy linkage')
    actual = {'report':report_row,'execution':execution_row,'controller_job_id':job}
    source = single_literal(template, 'ACTUAL_COMPLETION', actual)
    source_row = desc(COLLECTOR_ROOT/'source/collect_actual_post_originals.py', source)
    archive_request = {'schema':'hepta.runtime-properties-r10.post-comparison-archive-request.v1',
        'collector_source':source_row,**actual,
        'controller_status':desc(COLLECTOR_ROOT/'controller-status.original.json', status_raw),
        'controller_read':desc(COLLECTOR_ROOT/'controller-read.original.json', read_raw)}
    archive_raw = enc(archive_request);request_row = desc(COLLECTOR_ROOT/'ARCHIVE-REQUEST.json', archive_raw)
    files = {'p4/source/collect_actual_post_originals.py':source,
        'p4/controller-status.original.json':status_raw,'p4/controller-read.original.json':read_raw,
        'p4/ARCHIVE-REQUEST.json':archive_raw}
    result = {'phase':'collector','actual_completion':actual,'source':source_row,'request':request_row,
        'p4_create_only_root':str(COLLECTOR_ROOT),'collector_fixed_out':str(EVIDENCE),
        'argv':['/usr/bin/python3','-I','-B',source_row['path'],'--request',request_row['path'],
            '--request-sha256',request_row['sha256'],'--execute-host-archive'],
        'p4_payload':[{ 'relative':name.removeprefix('p4/'),
            'local':desc(out/name,raw),'destination':desc(COLLECTOR_ROOT/name.removeprefix('p4/'),raw)}
            for name,raw in sorted(files.items())]}
    return files, result


def proof_capacity(index, capacity, result):
    need(index['schema']=='hepta.runtime-properties-r10.adoption-proof-inputs.v1'
        and index['comparison_kind']=='post_live_export', 'actual post proof index')
    rows = index['files']
    need(type(rows) is list and 4<=len(rows)<=512, 'final verifier proof path-count bound')
    for row in rows:exact3(row)
    need(len({row['path'] for row in rows})==len(rows)
        and index['origin_map']==[{'original':row,'retained':row} for row in rows], 'exact unique original P4 proof map')
    total = sum(row['bytes'] for row in rows)
    need(total<=16*1024*1024, 'final verifier sum of all proof path bytes exceeds16MiB')
    objects = {}
    for row in rows:
        need(row['sha256'] not in objects or objects[row['sha256']]==row['bytes'], 'same SHA has inconsistent sizes')
        objects[row['sha256']] = row['bytes']
    need(capacity['file_descriptors']==len(rows) and capacity['unique_sha256_objects']==len(objects)
        and capacity['raw_unique_bytes']==sum(objects.values())
        and capacity['base64_unique_bytes']==sum(4*((size+2)//3) for size in objects.values())
        and capacity['transfer_packet_gzip_bytes']==result['proof_packet']['bytes']<=16*1024*1024
        and type(capacity['transfer_packet_expanded_bytes']) is int
        and 0<capacity['transfer_packet_expanded_bytes']<=64*1024*1024,
        'actual packet capacity must fit unchanged mirror bounds')
    for key in ('complete_archive','complete_archive_manifest'):
        maximum = 256*1024*1024 if key=='complete_archive' else 32*1024*1024
        exact3(index[key], maximum=maximum)
        need(index[key]['bytes']>0, 'nonempty complete archive reference')
    need(result['full_archive']==index['complete_archive']
        and result['full_archive_manifest']==index['complete_archive_manifest'], 'complete archive linkage')
    return {'proof_paths':len(rows),'proof_path_bytes':total,'unique_objects':len(objects),
        'unique_bytes':sum(objects.values()),'compressed_packet_bytes':result['proof_packet']['bytes'],
        'expanded_packet_bytes':capacity['transfer_packet_expanded_bytes'],
        'complete_archive_bytes':index['complete_archive']['bytes']}


def mirror(o, request, out):
    need(set(request)=={'schema','phase','template','report_copy','collector_result_copy',
        'proof_index_copy','capacity_copy'}, 'exact mirror binding input fields')
    template = o.read(request['template'])
    need(bp(request['template'])==MIRROR_PIN, 'reviewed0374 mirror template required')
    result = strict(o.read(request['collector_result_copy']))
    index = strict(o.read(request['proof_index_copy']));capacity = strict(o.read(request['capacity_copy']))
    report = strict(o.read(request['report_copy']))
    need(result['schema']=='hepta.runtime-properties.complete-original-preservation.v1'
        and result['state']=='COMPLETE' and result['source_originals_preserved'] is True
        and result['original_raw_reports_rewritten'] is False, 'actual collector completion')
    wanted = {'report':str(ACTUAL/'comparison/RESULT.json'),
        'proof_index':str(EVIDENCE/'ADOPTION-PROOF-INPUTS.P4.json'),
        'capacity':str(EVIDENCE/'VERIFICATION-ORIGINALS-CAPACITY.json'),
        'proof_packet':str(EVIDENCE/'PROOF-ORIGINALS.packet.json.gz')}
    for key,path in wanted.items():
        exact3(result[key]);need(result[key]['path']==path, 'fixed actual collector output path')
    for key,copy_key in [('report','report_copy'),('proof_index','proof_index_copy'),('capacity','capacity_copy')]:
        need(bp(result[key])==bp(request[copy_key]), 'actual copied collector output identity')
    need(index['report']==result['report'] and report['comparison_kind']=='post_live_export'
        and report['check_count']==report['passed_count']==16
        and bp(report['candidate'])==ACTUAL_POLICY_PIN, 'actual post report proof linkage')
    counts = proof_capacity(index, capacity, result)
    live_row,live = live_originals(o)
    applied = report['sources']['applied_verifier_source'];independent = report['sources']['live_provenance_verifier']
    applied_retained = live['originals']['policy_runtime_properties_verifier.original.py']
    independent_retained = live['independent_verifier_source']
    need(bp(applied)==APPLIED_PIN and bp(independent)==INDEPENDENT_PIN
        and [row for row in index['files'] if row['sha256']==APPLIED_PIN['sha256']]==[applied]
        and [row for row in index['files'] if row['sha256']==INDEPENDENT_PIN['sha256']]==[independent],
        'one exact applied and independent source each in actual proof')
    actual = {'packet':result['proof_packet'],'original_index':result['proof_index'],'report':result['report'],
        'collector_result':{'path':str(EVIDENCE/'RESULT.json'),**bp(request['collector_result_copy'])},
        'capacity':result['capacity'],'verifier_original':applied,'verifier_retained':applied_retained,
        'independent_verifier_original':independent,'independent_verifier_retained':independent_retained}
    source = single_literal(template, 'ACTUAL_PROOF', actual)
    source_row = desc(out/'source/mirror_actual_post_proof.py', source)
    mirror_request = {'schema':'hepta.runtime-properties-r10.post-proof-mirror-request.v2','source':source_row,**actual}
    request_raw = enc(mirror_request);request_row = desc(out/'MIRROR-REQUEST.json', request_raw)
    return {'source/mirror_actual_post_proof.py':source,'MIRROR-REQUEST.json':request_raw}, {
        'phase':'mirror','actual_proof':actual,'source':source_row,'request':request_row,
        'actual_live_provenance':live_row,'capacity_precheck':counts,'mirror_fixed_out':str(MIRROR_OUT),
        'argv':['/usr/bin/python3','-I','-B',source_row['path'],'--request',request_row['path'],
            '--request-sha256',request_row['sha256'],'--execute-host-mirror']}


def adoption_collection(o, request, out):
    need(set(request)=={'schema','phase','mirror_result'}, 'exact adoption collection preparation fields')
    need(request['mirror_result']['path']==str(MIRROR_OUT/'MIRROR-RESULT.json'), 'actual fixed mirror result')
    result = strict(o.read(request['mirror_result']))
    need(result['schema']=='hepta.runtime-properties.actual-proof-mirror.v1'
        and result['state']=='ACTUAL_ORIGINALS_MIRRORED'
        and result['all_retained_bytes_and_metadata_rechecked'] is True
        and result['original_raw_reports_rewritten'] is False and result['policy_adoption_recorded'] is False,
        'actual completed mirror required')
    index_row = result['index'];index = strict(o.read(index_row))
    need(index_row['path']==str(MIRROR_OUT/'ADOPTION-PROOF-INPUTS.json')
        and index['comparison_kind']=='post_live_export' and 4<=len(index['files'])<=512
        and sum(row['bytes'] for row in index['files'])<=16*1024*1024, 'actual bounded Mac post proof')
    live_row,live = live_originals(o)
    need(result['existing_captured_verifier']==live['originals']['policy_runtime_properties_verifier.original.py']
        and result['existing_independent_verifier']==live['independent_verifier_source'], 'mirror canonical source aliases')
    offline_row = {'path':str(B/'policy-runtime-properties-r10-offline-proof01/ADOPTION-PROOF-INPUTS.json'),**OFFLINE_PIN}
    offline = strict(o.read(offline_row))
    need(offline['comparison_kind']=='offline_candidate', 'retained fixed offline comparison proof')
    manifest_row = {'path':str(INDEPENDENT_ROOT/'SOURCE-MANIFEST.json'),**INDEPENDENT_MANIFEST_PIN}
    manifest = strict(o.read(manifest_row));rows = {row['path']:row for row in manifest['files']}
    for name in ('policy_runtime_properties_verifier.py','runtime_properties_host_originals.py',
        'make_runtime_properties_adoption_inputs.py','make_runtime_properties_adoption.py'):
        row = rows['source/'+name];o.read({'path':str(INDEPENDENT_ROOT/'source'/name),**bp(row)})
    plan = {'schema':'hepta.runtime-properties-r10.adoption-input-collection-plan.v1',
        'live_provenance':live_row,'offline_proof_inputs':offline_row,'post_live_proof_inputs':index_row}
    plan_raw = enc(plan);plan_row = desc(out/'ADOPTION-COLLECTION-PLAN.json', plan_raw)
    return {'ADOPTION-COLLECTION-PLAN.json':plan_raw}, {'phase':'adoption-collection',
        'plan':plan_row,'actual_policy':ACTUAL_POLICY_PIN,'independent_source_manifest':manifest_row,
        'argv':['/usr/bin/python3','-I','-B',str(INDEPENDENT_ROOT/'source/make_runtime_properties_adoption_inputs.py'),
            '--plan',plan_row['path'],'--plan-sha256',plan_row['sha256'],
            '--out',str(out/'ADOPTION-INPUTS.json'),'--execute-host-inputs'],
        'native_adoption_entry':str(INDEPENDENT_ROOT/'source/make_runtime_properties_adoption.py'),
        'adoption_inputs_future_path':str(out/'ADOPTION-INPUTS.json'),
        'adoption_requires_actual_new_inputs_sha256':True,
        'explicit_root_expected_actual_policy_sha256':ACTUAL_POLICY_PIN['sha256']}


def write_new(out, files):
    need(out.is_absolute() and out!=B and out.is_relative_to(B)
        and out.parent.resolve(strict=True)==out.parent and not out.exists() and not out.is_symlink(),
        'new canonical Mac project preparation output')
    os.umask(0o077);out.mkdir(mode=0o700)
    def sync(path):
        fd = os.open(path, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)
    sync(out.parent)
    for name,raw in sorted(files.items()):
        relative = Path(name)
        need(not relative.is_absolute() and '..' not in relative.parts, 'new local relative output')
        parent = out
        for component in relative.parts[:-1]:
            child = parent/component
            if not child.exists():child.mkdir(mode=0o700);sync(parent)
            need(child.resolve(strict=True)==child and child.is_dir(), 'canonical preparation subdirectory')
            parent = child
        path = out/relative
        fd = os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC, 0o600)
        with os.fdopen(fd, 'wb') as stream:stream.write(raw);stream.flush();os.fsync(stream.fileno())
        sync(path.parent);need(path.read_bytes()==raw, 'new preparation original readback')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs-desc', required=True, help='JSON exact3 descriptor of the local binding-input JSON')
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--write-source-only', action='store_true')
    args = parser.parse_args(argv)
    o = Originals();input_row = strict(args.inputs_desc);request = strict(o.read(input_row))
    need(request['schema']==SCHEMA and request['phase'] in ('collector','mirror','adoption-collection'),
        'exact supported source-only binding request')
    need(args.out.is_absolute() and args.out.is_relative_to(B) and args.out!=B, 'explicit new Mac preparation path')
    operation = {'collector':collector,'mirror':mirror,'adoption-collection':adoption_collection}[request['phase']]
    files,result = operation(o, request, args.out)
    result.update(schema='hepta.runtime-properties-r10.post-evidence-source-preparation.v1',
        state='SOURCE_ONLY_PREVIEW_NO_REMOTE_OR_ADOPTION',binding_inputs=input_row,
        remote_calls=0,phone_calls=0,comparison_processes=0,retention_executions=0,
        archive_executions=0,mirror_executions=0,adoption_writes=0,automatic_retry=False,
        fixed_namespaces_must_be_reconciled_by_root_before_execution=True)
    files['BINDING-INPUTS.original.json'] = o.read(input_row)
    o.recheck()
    if args.write_source_only:
        result['state'] = 'SOURCE_ONLY_PREPARED_NO_REMOTE_OR_ADOPTION'
        files['PREPARATION-RESULT.json'] = enc(result)
        write_new(args.out, files);o.recheck()
    print(json.dumps(result, sort_keys=True));return 0


if __name__=='__main__':
    raise SystemExit(main())
