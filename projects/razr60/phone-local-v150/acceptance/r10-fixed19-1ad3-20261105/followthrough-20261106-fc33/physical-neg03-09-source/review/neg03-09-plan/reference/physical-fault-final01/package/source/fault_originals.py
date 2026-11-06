#!/usr/bin/env python3
"""Pure exact-original utilities reused for the separate physical-fault closer."""
import ast,base64,copy,fnmatch,gzip,hashlib,io,json,re,shlex,stat,types,zlib
from pathlib import PurePosixPath as Path
BASE='/var/lib/trillionnium/owner-open/phone-local-v150'
P4='/home/alex/razr60-local-model-v150'
B='/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
SCOPE=('session_id','profile_id','task_id','turn_id','turn_stream_id')
MAX_FILE=16*1024*1024
MAX_ARCHIVE=64*1024*1024
MAX_EXPANDED_TAR=72*1024*1024
MAX_INPUT=192*1024*1024
EMPTY_SHA=hashlib.sha256(b'').hexdigest()
class Unverified(ValueError):
    pass

def need(value, code):
    if not value:
        raise Unverified(code)

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict(raw):
    def pairs(rows):
        value = {}
        for key,item in rows:
            need(key not in value, 'duplicate_json_key')
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(Unverified('nonfinite_json')))

def encoded(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,separators=(',',':'),
                       allow_nan=False)+'\n').encode()

def pretty(value):
    return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,
                       allow_nan=False)+'\n').encode()

def same(left,right):
    return encoded(left) == encoded(right)

def number(value, minimum=0, maximum=2**63-1):
    return type(value) is int and minimum <= value <= maximum

def digest(value):
    need(type(value) is str and re.fullmatch('[0-9a-f]{64}',value), 'sha256_shape')
    return value

def canonical(path):
    need(type(path) is str and path.startswith('/') and '\0' not in path and
         str(Path(path)) == path and '..' not in Path(path).parts, 'canonical_absolute_path')
    return path

def relative(path):
    need(type(path) is str and not path.startswith('/') and
         re.fullmatch(r'[A-Za-z0-9._/-]{1,1024}',path) and
         all(p not in ('','.','..') for p in path.split('/')), 'archive_relative_path')
    return path

def exact3(row, maximum=MAX_FILE):
    need(type(row) is dict and set(row)=={'path','bytes','sha256'}, 'exact_descriptor')
    canonical(row['path'])
    need(number(row['bytes'],0,maximum), 'original_byte_bound')
    digest(row['sha256'])
    return row

def bytes_pin(row, maximum=MAX_FILE):
    need(type(row) is dict and set(row)=={'bytes','sha256'} and
         number(row['bytes'],0,maximum), 'byte_descriptor')
    digest(row['sha256'])
    return row

def metadata(row, directory=False):
    need(type(row) is dict and set(row)==set(META) and
         all(type(v) is int for v in row.values()), 'full9_dictionary')
    need((stat.S_ISDIR if directory else stat.S_ISREG)(row['st_mode']) and
         row['st_dev']>=0 and row['st_ino']>0 and row['st_uid']>=0 and row['st_gid']>=0,
         'original_metadata_type')
    if not directory:
        need(row['st_nlink']==1 and row['st_size']>=0, 'original_single_link')
    return row

class Originals:
    def __init__(self, callback):
        self.callback=callback
        self.seen={}
        self.total=0
    def read(self,row,maximum=MAX_FILE):
        exact3(row,maximum)
        raw=self.callback(row)
        need(type(raw) is bytes and len(raw)==row['bytes'] and sha(raw)==row['sha256'],
             'original_pin_or_readback')
        old=self.seen.get(row['path'])
        need(old is None or old==(dict(row),raw), 'original_changed_between_reads')
        if old is None:
            self.total+=len(raw)
            need(self.total<=MAX_INPUT, 'host_original_pool_bound')
            self.seen[row['path']]=(dict(row),raw)
        return raw
    def recheck(self):
        for row,raw in tuple(self.seen.values()):
            need(self.callback(row)==raw, 'original_changed_at_final_bookend')
    def index(self):
        return [row for row,_ in sorted(self.seen.values(),key=lambda x:x[0]['path'])]

def literal(raw,name):
    nodes=[n for n in ast.parse(raw).body if isinstance(n,ast.Assign) and
           len(n.targets)==1 and isinstance(n.targets[0],ast.Name) and n.targets[0].id==name]
    need(len(nodes)==1, 'unique_source_literal')
    return ast.literal_eval(nodes[0].value)

def source_segment(raw,name,classname=None):
    tree=ast.parse(raw)
    nodes=tree.body
    if classname:
        rows=[n for n in nodes if isinstance(n,ast.ClassDef) and n.name==classname]
        need(len(rows)==1,'unique_reviewed_class')
        nodes=rows[0].body
    rows=[n for n in nodes if isinstance(n,ast.FunctionDef) and n.name==name]
    need(len(rows)==1,'unique_reviewed_function')
    return ast.get_source_segment(raw.decode(),rows[0])

def host_capture(raw,records,child,result,intent_raw,stdout,stderr):
    value=strict(raw)
    fields={'schema','phase','pid','source_intent_sha256','output_limit_bytes_per_stream',
        'worker_started','worker_joined','pipe_reader_owner','child_wait_returned','child_returncode',
        'child_join_observed_monotonic','execution_deadline_monotonic','deadline_validity',
        'stdout_eof','stderr_eof','eof_observed_monotonic','prefix_only_or_unknown','captured','files',
        'error','persist_errors','pipe_close_errors','automatic_retry','signals_sent',
        'remote_terminal_or_cleanup_proven'}
    need(type(value) is dict and set(value)==fields and raw==pretty(value),
         'exact_original_capture_sidecar')
    need(value['schema']=='hepta.native-guard.host-output-capture.v1' and
         value['phase']==result['phase'] and value['pid']==child['pid']==result['pid'] and
         value['source_intent_sha256']==sha(intent_raw) and
         value['output_limit_bytes_per_stream']==64*1024*1024,
         'capture_phase_child_intent_bound')
    need(value['worker_started'] is True and value['worker_joined'] is True and
         value['pipe_reader_owner']=='closed_by_worker' and value['child_wait_returned'] is True and
         type(value['child_returncode']) is int and value['child_returncode']==0 and
         value['stdout_eof'] is True and value['stderr_eof'] is True and
         value['prefix_only_or_unknown'] is False and value['error'] is None and
         value['persist_errors']==value['pipe_close_errors']==[] and value['automatic_retry'] is False and
         value['signals_sent']==0 and value['remote_terminal_or_cleanup_proven'] is False,
         'capture_not_complete_or_unknown')
    deadline=value['execution_deadline_monotonic']
    need(type(deadline) in (int,float) and 0<deadline<float('inf') and
         child.get('execution_deadline_monotonic')==deadline and
         value['deadline_validity']==child.get('deadline_validity')=='this_running_coordinator_only',
         'same_original_capture_deadline')
    eof=value['eof_observed_monotonic'];joined=value['child_join_observed_monotonic']
    need(type(eof) is dict and set(eof)=={'stdout','stderr'} and
         all(type(t) in (int,float) and 0<t<=deadline for t in [joined,*eof.values()]),
         'child_join_or_EOF_after_original_deadline')
    need(set(value['captured'])==set(value['files'])=={'stdout','stderr'} and
         type(child.get('original_output_identities')) is dict and
         set(child['original_output_identities'])=={'stdout','stderr'},
         'both_original_capture_streams_required')
    same_inode=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink')
    for label,body in (('stdout',stdout),('stderr',stderr)):
        wanted={'bytes':len(body),'sha256':sha(body)}
        need(value['captured'][label]==wanted,'actual_output_differs_from_captured_pipe')
        file=value['files'][label]
        need(type(file) is dict and set(file)=={'path','bytes','sha256','metadata','original_created_inode_bound'}
             and {k:file[k] for k in ('path','bytes','sha256')}==records[label] and
             file['original_created_inode_bound'] is True,'captured_output_original_path_or_inode')
        initial=metadata(child['original_output_identities'][label]);final=metadata(file['metadata'])
        need(initial['st_size']==0 and final['st_size']==len(body) and
             stat.S_IMODE(initial['st_mode'])==stat.S_IMODE(final['st_mode'])==0o600 and
             all(initial[k]==final[k] for k in same_inode),
             'created_output_inode_not_retained_through_complete_capture')
    return value

def host_phase(originals, records, phase, argv, timeout, stdin):
    need(type(records) is dict and set(records)=={'intent','child','result','stdout','stderr','stdin','output_capture'},
         'original_host_phase_fields_with_capture')
    raws={k:originals.read(v,MAX_ARCHIVE if k=='stdout' else MAX_FILE)
          for k,v in records.items() if v is not None}
    need(set(raws)==({'intent','child','result','stdout','stderr','output_capture'} |
                    ({'stdin'} if stdin is not None else set())),
         'original_host_phase_complete')
    directory=Path(records['intent']['path']).parent
    need(directory.name==phase,'original_phase_directory_name')
    for key,leaf in (('intent','INTENT.json'),('child','CHILD.json'),('result','RESULT.json'),
                     ('stdout','stdout.original'),('stderr','stderr.original'),
                     ('output_capture','OUTPUT-CAPTURE.json')):
        need(records[key]['path']==str(directory/leaf),'original_phase_member_exact_path')
    if stdin is not None:
        need(records['stdin']['path']==str(directory/'stdin.original'),'original_stdin_member_path')
    intent,child,result=[strict(raws[k]) for k in ('intent','child','result')]
    wanted={'schema':'hepta.native-guard.root-host-command.v1','phase':phase,
        'argv':argv,'stdin_sha256':None if stdin is None else sha(stdin),
        'maximum_starts':1,'maximum_wait_seconds':timeout,'automatic_retry':False,'signals_on_timeout':False,
        'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
        'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
        'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
        'output_limit_bytes_per_stream':64*1024*1024,'hard_bound_on_filesystem_spawn_or_cleanup':False}
    need(intent==wanted and raws['intent']==pretty(intent),'original_host_capture_intent_exact')
    if stdin is not None:
        need(raws['stdin']==stdin,'original_host_stdin_exact')
    need(number(child.get('pid'),2) and child.get('source_intent_sha256')==sha(raws['intent']) and
         child.get('maximum_starts')==1,'original_host_child_identity')
    missing=child.get('identity_missing_only_if_actual_child_already_joined')
    need((missing is False and child.get('pgid')==child['pid']==child.get('sid')) or
         (missing is True and child.get('pgid') is None and child.get('sid') is None),
         'original_host_child_group')
    need(set(result)=={'state','phase','pid','returncode','stdout','stderr','automatic_retry'} and
         result.get('state')=='ORIGINAL_HOST_CHILD_JOINED' and result.get('phase')==phase and
         result.get('pid')==child['pid'] and type(result.get('returncode')) is int and
         result['returncode']==0 and result.get('automatic_retry') is False and
         result.get('stdout')==records['stdout'] and result.get('stderr')==records['stderr'] and
         raws['stderr']==b'', 'original_host_terminal_not_joined_zero')
    host_capture(raws['output_capture'],records,child,result,raws['intent'],raws['stdout'],raws['stderr'])
    return raws['stdout']

def unpack_archive(raw):
    """Bounded one-gzip, regular-only complete tar; no filesystem extraction."""
    import tarfile
    need(type(raw) is bytes and 0<len(raw)<=MAX_ARCHIVE,'compressed_archive_bound')
    dec=zlib.decompressobj(31)
    plain=dec.decompress(raw,MAX_EXPANDED_TAR+1)
    need(len(plain)<=MAX_EXPANDED_TAR and dec.eof and not dec.unused_data and
         not dec.unconsumed_tail,'single_bounded_gzip_archive')
    members={}
    with tarfile.open(fileobj=io.BytesIO(plain),mode='r:') as archive:
        for item in archive:
            name=relative(item.name)
            need(name not in members and len(members)<2065 and item.isfile() and
                 item.type==tarfile.REGTYPE and item.linkname=='' and item.mode==0o600 and
                 item.uid==0 and item.gid==0 and item.mtime==0 and
                 set(item.pax_headers)<= {'path'} and
                 item.pax_headers.get('path',name)==name and
                 0<=item.size<=MAX_ARCHIVE, 'archive_member_type_or_duplicate')
            stream=archive.extractfile(item)
            need(stream is not None,'archive_regular_body')
            body=stream.read(item.size+1)
            need(len(body)==item.size,'archive_member_short')
            members[name]=body
    need(members and sum(map(len,members.values()))<=MAX_ARCHIVE+4*1024*1024,
         'complete_archive_raw_bound')
    return members

def file_row(row, members):
    need(type(row) is dict and set(row)=={'source','bytes','sha256','metadata','retained'},
         'source_retained_row_fields')
    canonical(row['source']);metadata(row['metadata'])
    rel=row['retained'];need(type(rel) is dict and set(rel)=={'path','bytes','sha256'},'archive_retained_descriptor')
    name=relative(rel['path'])
    need(name in members and len(members[name])==row['bytes']==rel['bytes']==row['metadata']['st_size'] and
         sha(members[name])==row['sha256']==rel['sha256'],'archive_source_row_integrity')
    return members[name]

def directory_row(row, source, names):
    need(type(row) is dict and set(row)=={'source','metadata_before','metadata_after','names_before','names_after'} and
         row['source']==source,'directory_record_fields')
    metadata(row['metadata_before'],True)
    need(same(row['metadata_before'],row['metadata_after']) and
         row['names_before']==row['names_after']==sorted(names) and len(set(names))==len(names),
         'complete_original_directory_bookends')
    for name in names:
        need(type(name) is str and re.fullmatch('[A-Za-z0-9._-]{1,192}',name) and name not in ('.','..'),
             'original_flat_directory_name')

def source_rows(value):
    rows=[]
    def walk(item):
        if type(item) is dict:
            if set(item)=={'source','bytes','sha256','metadata','retained'}:
                rows.append(item)
            else:
                for child in item.values():walk(child)
        elif type(item) is list:
            for child in item:walk(child)
    walk(value)
    return rows
