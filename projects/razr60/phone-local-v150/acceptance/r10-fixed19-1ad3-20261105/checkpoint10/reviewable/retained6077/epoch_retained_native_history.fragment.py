# Independent pure retained-failed-native history delegation; no I/O or target execution.
# External source binding is deliberately None until actual complete evidence is reviewed.
import hashlib as _ehn_hashlib
import json as _ehn_json
import math as _ehn_math
from pathlib import PurePosixPath as _EhnPath
import re as _ehn_re
import stat as _ehn_stat
EPOCH_RETAINED_NATIVE_HISTORY_AUTHORITY_BINDING = None
EPOCH_RETAINED_NATIVE_HISTORY_INPUT_FIELDS = ('schema', 'epoch_id', 'label', 'nonce', 'boot_id', 'authority', 'original_closure', 'originals')
EPOCH_RETAINED_NATIVE_HISTORY_ROLES = ('auditor_source', 'caller_source', 'source_manifest', 'original_closer_source', 'bootstrap_source', 'controller_request', 'controller_start', 'controller_status', 'controller_read', 'controller_stdout', 'controller_stderr', 'stage_intent', 'stage_result', 'stage_returned', 'caller_sources', 'caller_result', 'child_intent', 'child_identity', 'child_result', 'child_capture', 'child_stdout', 'child_stderr', 'parent_names_before', 'parent_names_after', 'original_closure', 'original_plan', 'original_package')
_EHN_CARRIER_ROOT = '/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/epoch-retained6077-history-carriers-1ad3-01'
_EHN_BASE = '/home/alex'
_EHN_SOURCE = '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01'
_EHN_CALLER_OUT = '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01'
_EHN_AUDIT_OUT = '/home/alex/codex-hepta-diag6077-independent-closure-audit-1ad3-01'
_EHN_STAGE_ROOT = '/home/alex/codex-hepta-diag6077-independent-closure-audit-stage-1ad3-01'
_EHN_OLD_BASE = '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8'
_EHN_PHASE = 'retained6077-history-audit'
_EHN_BOOT = 'f8019f83-20a7-4f18-bea1-51c980621e4d'
_EHN_NONCE = '6077fc8f045572edc4acfb13ed7e09a8'
_EHN_LABEL = 'root-r10-neg01-7c907661-diag01'
_EHN_COMBINATION = 'b4d4a221a4a516177cecf8e182a7ee9a494fc65feb85277cfdf10d28396d5709'
_EHN_SOURCE_PINS = {'auditor_source': {'path': '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/audit_existing_closure.py', 'bytes': 26036, 'sha256': '4d584a8325e7fadd64d0a87d369ef51b3573087fce661fa0d95a2c58ddf33577'}, 'caller_source': {'path': '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/run_retained_failed_native_history_owned_once.py', 'bytes': 63287, 'sha256': 'cd2091df02ba3a68d1be676544cf288905fdda313c239ae6375bbd0324582c36'}, 'source_manifest': {'path': '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/SOURCE-MANIFEST.json', 'bytes': 539, 'sha256': '600f65549a7f25dd1dfef6945e0b6dd1d416f971392cce0d4131d0c43c240ff9'}, 'original_closer_source': {'bytes': 99120, 'path': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/material/tree/package/source/close_component.py', 'sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1'}}
_EHN_BOOTSTRAP_PIN = {'bytes': 125497, 'sha256': '64c12410d6e5e921e54dfc562044c0b11329beed4b3eb0f5fe0f07aea7ea7919'}
_EHN_REQUEST_PIN = {'bytes': 126312, 'sha256': '812c321e32982304f7188b356d2b9156995212429f744c2ddec202c7f216c2af'}
_EHN_BOOTSTRAP_HEADER = "import hashlib,sys\nbody=sys.stdin.buffer.read(131073)\nassert len(body)==125497 and hashlib.sha256(body).hexdigest()=='64c12410d6e5e921e54dfc562044c0b11329beed4b3eb0f5fe0f07aea7ea7919'\nexec(compile(body,'<fixed-retained6077-owned-audit-bootstrap>','exec'),{'__name__':'__main__','BOOTSTRAP_SOURCE':body})\n"
_EHN_OWNED_ARGV = ['/usr/bin/python3', '-I', '-B', '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/run_retained_failed_native_history_owned_once.py', '--source-manifest-sha256', '600f65549a7f25dd1dfef6945e0b6dd1d416f971392cce0d4131d0c43c240ff9', '--execute-fixed-owned-history-once']
_EHN_ARGV = ['/usr/bin/python3', '-I', '-B', '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/audit_existing_closure.py', '--execute-independent-host-audit-once']
_EHN_META_KEYS = ('st_dev', 'st_ino', 'st_mode', 'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
_EHN_CLOSURE_PIN = {'bytes': 55184, 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'}
_EHN_PLAN_PIN = {'bytes': 2609, 'sha256': 'bb11e33d93583d0fa645cc76e078b6126c02de2a88f9afae7959ea43edd7f667'}
_EHN_PACKAGE_PIN = {'bytes': 18864, 'sha256': '8b9a3b24f2449022120f7f1ef15905ee9a07edac8062fcf46cf7bb0b0c8e7302'}
_EHN_CAPTURE_PIN = {'bytes': 147334, 'sha256': 'ed525e3fb997cf342fc7b31b1cb7f97723f5f17cceda82faa9ab969188b2fb7b'}
_EHN_ARCHIVE = {'bytes': 2412565, 'path': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/closure-inputs/ORIGINALS.tar.gz', 'sha256': 'ec20f762bb98bfc93a96c9693ef63d702d2b36e2fd896408c6e919ae46a1fbad'}
_EHN_AUDIT_PINS = {'AUDIT-INTENT.json': {'bytes': 1401, 'sha256': 'd136d3de6b94dbcb429a85a41ad0b45e9f10d98183e3264fad9e1e139b6a2716'}, 'RECOMPUTED-AFTER-INVENTORY.json': {'bytes': 996847, 'sha256': '4d64153c7cecf0782bb804791cf272e01ca83ae0b36d9927096762cc3fafc228'}, 'RECOMPUTED-EXPECTED-CLOSURE.json': {'bytes': 55184, 'sha256': '35af6a58a84413770bb14ede44eca83ac2774cd4591c7df1501b501cb1643335'}, 'RECOMPUTED-NATIVE-AUDIT.json': {'bytes': 340, 'sha256': '98cff3187f1a7da1c0a528a0d1a2a9630127c9a0da05a62b980b70363b74648d'}, 'derived/semantic-f0880307640e4cd919dc1797cdbdf75d1f56e581cc3b4938dfb9ffc4c10a1070.json': {'bytes': 6919, 'sha256': '890d4e9f518422712ebae572b543ff8d887f5f19e07eabf0ccfba02c08df5d57'}, 'sender-originals/ACTOR.original.py': {'bytes': 82969, 'sha256': '213e3683776aeb52fb34fc7a4be7e90cef3531c7140dca7d0fd31704d23d54ae'}, 'sender-originals/COMPONENT-FINAL-PRE-SEND-SELECTED.original-read.json': {'bytes': 727, 'sha256': '104c759a98e75c915fdc8e8d56279ae522848dc489c8da49bae4ec3676205491'}, 'sender-originals/DRAFT-RESTORE-RESULT.json': {'bytes': 222, 'sha256': '48b1e1f4865919702ef7c57cabfcd978d32f6d967de47e500bff9870fb6e8db1'}, 'sender-originals/FINAL-PRE-SEND-SELECTED.original-read.json': {'bytes': 727, 'sha256': '104c759a98e75c915fdc8e8d56279ae522848dc489c8da49bae4ec3676205491'}, 'sender-originals/HOST-ONCE.original.json': {'bytes': 1182, 'sha256': '897e31958a8e9c60bb6e01b2c6b19a76c439470479f5a42613862199b2d2b1d5'}, 'sender-originals/HOST-SEND-RESULT.original.json': {'bytes': 703, 'sha256': 'e61b442e9040f8775d879c54756b2ea523440578f46c814fbda972b247c231b7'}, 'sender-originals/LATENCY-0012.original-read.json': {'bytes': 36995, 'sha256': '85b1b72c87b499674e7061eaa1c56aae706d7f8810a4da6a0d60abf263b08d61'}, 'sender-originals/PRESERVED-DRAFT-RESTORE.original.json': {'bytes': 1206, 'sha256': '7177a9e695f1fd4080adb94f004f1455e4a0ceaa5b434606a80ed90c1eecbca9'}, 'sender-originals/PRESERVED-DRAFT.original.json': {'bytes': 282, 'sha256': '9d801d675a461de996206b1bdc911309aeb40df599c49860ddc9699779d4e741'}, 'sender-originals/PRESERVED-USER-DRAFT.json': {'bytes': 180, 'sha256': 'b60c6be1928d5490e6ebd57dba67769796a779e5e58eefeb7fb70f071348b661'}, 'sender-originals/PREVIOUS.original.json': {'bytes': 1428, 'sha256': '7c9fc15c9461613c4fb20950ad6762b0c88ab8a7be442acfe589f6f2da93f870'}, 'sender-originals/RESTORE-GLOBAL-GATE.original-read.json': {'bytes': 27050, 'sha256': '8d16a5a7c2ce0b0a6f68eecfae4e8b535d9a8ee42b2e600e2735944e5e3be2c8'}, 'sender-originals/RESTORE-SELECTED-FINAL.original-read.json': {'bytes': 727, 'sha256': '35c65e1ca2f74fb47b54f931b9e43a62090938ac8bfe0726e0049dc4fa59d696'}, 'sender-originals/RESTORE-SELECTED.original-read.json': {'bytes': 727, 'sha256': '35c65e1ca2f74fb47b54f931b9e43a62090938ac8bfe0726e0049dc4fa59d696'}, 'sender-originals/SEND-NATIVE-LATENCY.json': {'bytes': 14485, 'sha256': '991ebee42ea591b8c635394101a471d894d254020e31d10aac571abccfc69bee'}, 'sender-originals/SEND.MONOTONIC-INTENT.json': {'bytes': 106, 'sha256': 'c72dfce531921d5cb6ea4708c521263ad29266f1304cd295445d2c42c0a49826'}, 'sender-originals/SEND.MONOTONIC-WINDOW.json': {'bytes': 202, 'sha256': '16aa1875ee39fc6c3deb0b30ec1234d3abb84ba4a027f2cac5da95630070d32e'}, 'sender-originals/SEND.once.json': {'bytes': 562, 'sha256': '3ed9d8677abeac6ddbcffa48fb7a4a70d7a7f49b8ff443e9d3c125b5f13f8cb4'}, 'sender-originals/SEND.result.json': {'bytes': 119, 'sha256': 'b6af1b529caba4bda982249cd5fbaaa51632a354f3661b1f52cd1e2139af754a'}}
_EHN_CLOSED_EXPRESSION = {'source': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/material/tree/package/source/close_component.py', 'source_sha256': '9025acca896c501aef584a92e93af833a342c48731161a6ec10a4a1cae4278d1', 'first_line': 1352, 'last_line': 1376, 'bytes': 2141, 'sha256': '8472a436a3889fda2660ea8c77a6f163f824781b49ac5e9eb41c7733cf5b9344'}
_EHN_GUARD_MAP_SHA256 = 'aa3a7f4d1131979684ce4336aa40ca10a00a3fc1081d92639c1d24516934c3f9'
_EHN_FIXED_ROLE_PATHS = {'auditor_source': '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/audit_existing_closure.py', 'caller_source': '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/run_retained_failed_native_history_owned_once.py', 'source_manifest': '/home/alex/codex-hepta-diag6077-independent-closure-audit-source-1ad3-01/SOURCE-MANIFEST.json', 'original_closer_source': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/material/tree/package/source/close_component.py', 'bootstrap_source': '/home/alex/codex-hepta-diag6077-independent-closure-audit-stage-1ad3-01/BOOTSTRAP.original.py', 'stage_intent': '/home/alex/codex-hepta-diag6077-independent-closure-audit-stage-1ad3-01/INTENT.json', 'stage_result': '/home/alex/codex-hepta-diag6077-independent-closure-audit-stage-1ad3-01/SOURCE-STAGE-RESULT.json', 'stage_returned': '/home/alex/codex-hepta-diag6077-independent-closure-audit-stage-1ad3-01/OWNED-CALLER-RETURNED.json', 'caller_sources': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/SOURCE-OBSERVATIONS.json', 'caller_result': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/CALLER-RESULT.json', 'original_closure': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/closure/CLOSURE.original.json', 'original_plan': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/CLOSURE-PLAN.json', 'original_package': '/home/alex/codex-native-guard-chain-r10-r1/6077fc8f045572edc4acfb13ed7e09a8/material/tree/package/MANIFEST.json', 'child_intent': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/retained6077-history-audit/INTENT.json', 'child_identity': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/retained6077-history-audit/CHILD.json', 'child_result': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/retained6077-history-audit/RESULT.json', 'child_capture': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/retained6077-history-audit/OUTPUT-CAPTURE.json', 'child_stdout': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/retained6077-history-audit/stdout.original', 'child_stderr': '/home/alex/codex-hepta-diag6077-independent-closure-audit-owned-1ad3-01/retained6077-history-audit/stderr.original'}


def _ehn_need(condition, reason):
    if not condition:
        raise ValueError('epoch retained native history: '+reason)


def _ehn_encode(value):
    return (_ehn_json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False)+'\n').encode('utf-8')


def _ehn_equal(left,right):
    return _ehn_encode(left)==_ehn_encode(right)


def _ehn_strict(raw,maximum=16777216):
    _ehn_need(type(raw) is bytes and 0<len(raw)<=maximum,'bounded complete JSON original required')
    def pairs(items):
        result={}
        for key,value in items:
            _ehn_need(type(key) is str and key not in result,'duplicate JSON field')
            result[key]=value
        return result
    return _ehn_json.loads(raw.decode('utf-8','strict'),object_pairs_hook=pairs,
        parse_constant=lambda _: _ehn_need(False,'nonfinite JSON value'))


def _ehn_bare(raw):
    _ehn_need(type(raw) is bytes,'whole original body required')
    return {'bytes':len(raw),'sha256':_ehn_hashlib.sha256(raw).hexdigest()}


def _ehn_keys(value,keys,reason):
    _ehn_need(type(value) is dict and set(value)==set(keys),reason)
    return value


def _ehn_descriptor(value):
    _ehn_keys(value,('path','bytes','sha256'),'exact3 original descriptor required')
    path=value['path']
    _ehn_need(type(path) is str and path.startswith('/') and '\x00' not in path
        and str(_EhnPath(path))==path and '..' not in _EhnPath(path).parts
        and len(path.encode())<=4096,'canonical original path required')
    _ehn_need(type(value['bytes']) is int and 0<=value['bytes']<=16777216
        and type(value['sha256']) is str and _ehn_re.fullmatch('[0-9a-f]{64}',value['sha256']),
        'bounded typed original size/SHA required')
    return value


def _ehn_original(value):
    return _ehn_descriptor({key:value[key] for key in ('path','bytes','sha256')})


def _ehn_metadata(value,*,size=None,directory=False):
    _ehn_need(type(value) is list and len(value)==9 and all(type(x) is int and x>=0 for x in value),
        'complete actual host full9 required')
    _ehn_need((_ehn_stat.S_ISDIR(value[2]) if directory else _ehn_stat.S_ISREG(value[2]))
        and value[0]>0 and value[1]>0,'actual original metadata type differs')
    if not directory:
        _ehn_need(value[5]==1 and value[3:5]==[1000,1000] and not _ehn_stat.S_IMODE(value[2])&0o022,
            'actual P4 original private identity differs')
    if size is not None:_ehn_need(value[6]==size,'full9 size differs from complete body')
    return value


def _ehn_full4(value,original):
    _ehn_keys(value,('path','bytes','sha256','metadata'),'exact4 original observation required')
    _ehn_need(_ehn_equal(_ehn_original(value),original),'actual original path/bytes/SHA differs')
    _ehn_metadata(value['metadata'],size=original['bytes'])
    return value


def _ehn_flags(value,*,true=(),false=(),zero=()):
    for key in true:_ehn_need(value[key] is True,'true actual field required: '+key)
    for key in false:_ehn_need(value[key] is False,'false boundary field required: '+key)
    for key in zero:_ehn_need(type(value[key]) is int and value[key]==0,'strict zero required: '+key)


def _ehn_native(raw):
    outer=_ehn_strict(raw,1048576)
    _ehn_need(type(outer) is dict and outer.get('isError') is False
        and type(outer.get('content')) is list and len(outer['content'])==1,
        'complete successful native tool envelope required')
    item=outer['content'][0]
    _ehn_need(type(item) is dict and item.get('type')=='text' and type(item.get('text')) is str,
        'one native JSON body required')
    value=_ehn_strict(item['text'].encode(),524288)
    _ehn_need(type(value) is dict,'native result object required')
    return value


def _ehn_child(roles,raws):
    intent=_ehn_strict(raws['child_intent'],65536);child=_ehn_strict(raws['child_identity'],65536)
    capture=_ehn_strict(raws['child_capture'],65536);result=_ehn_strict(raws['child_result'],65536)
    expected={'schema':'hepta.native-guard.root-host-command.v1','phase':_EHN_PHASE,'argv':_EHN_ARGV,
        'stdin_sha256':None,'maximum_starts':1,'maximum_wait_seconds':100,'automatic_retry':False,
        'signals_on_timeout':False,'deadline_scope':'popen_start_through_child_join_pipe_eof_and_output_verification',
        'input_transport':'retained_readonly_regular_fd_child_reads_within_execution_budget',
        'output_transport':'owned_nonblocking_pipe_capture_worker_bounded_memory_main_thread_persistence',
        'output_limit_bytes_per_stream':65536,'hard_bound_on_filesystem_spawn_or_cleanup':False}
    _ehn_need(_ehn_equal(intent,expected),'actual 0374 fixed intent differs')
    intent_sha=_ehn_bare(raws['child_intent'])['sha256']
    _ehn_need(type(child['pid']) is int and child['pid']>1
        and all(type(child[k]) is int and child[k]==child['pid'] for k in ('pgid','sid'))
        and child['source_intent_sha256']==intent_sha and child['maximum_starts']==1
        and type(child['maximum_starts']) is int
        and child['identity_missing_only_if_actual_child_already_joined'] is False,
        'actual owned child process generation differs')
    _ehn_need(capture['schema']=='hepta.native-guard.host-output-capture.v1'
        and capture['phase']==_EHN_PHASE and type(capture['pid']) is int and capture['pid']==child['pid']
        and capture['source_intent_sha256']==intent_sha
        and capture['pipe_reader_owner']=='closed_by_worker'
        and type(capture['output_limit_bytes_per_stream']) is int and capture['output_limit_bytes_per_stream']==65536,
        'actual bounded owned output capture identity differs')
    _ehn_flags(capture,true=('worker_started','worker_joined','child_wait_returned','stdout_eof','stderr_eof'),
        false=('prefix_only_or_unknown','automatic_retry','remote_terminal_or_cleanup_proven'),
        zero=('child_returncode','signals_sent'))
    _ehn_need(capture['error'] is None and capture['persist_errors']==[] and capture['pipe_close_errors']==[],
        'capture has unresolved output/cleanup errors')
    deadline=capture['execution_deadline_monotonic']
    _ehn_need(type(deadline) in (int,float) and _ehn_math.isfinite(deadline) and deadline>0
        and _ehn_equal(deadline,child['execution_deadline_monotonic'])
        and capture['deadline_validity']=='this_running_coordinator_only'
        and child['deadline_validity']=='this_running_coordinator_only','owned deadline binding differs')
    for value in (capture['child_join_observed_monotonic'],*capture['eof_observed_monotonic'].values()):
        _ehn_need(type(value) in (int,float) and _ehn_math.isfinite(value) and 0<value<=deadline,
            'actual join and EOF must complete within their original deadline')
    for stream in ('stdout','stderr'):
        raw=raws['child_'+stream];file=capture['files'][stream]
        _ehn_need(len(raw)<=65536 and _ehn_equal(capture['captured'][stream],_ehn_bare(raw))
            and _ehn_equal(_ehn_original(file),roles['child_'+stream])
            and file['original_created_inode_bound'] is True,'complete held-inode child stream differs')
        _ehn_keys(file['metadata'],_EHN_META_KEYS,'captured stream full9 shape differs')
        meta=[file['metadata'][k] for k in _EHN_META_KEYS];_ehn_metadata(meta,size=len(raw))
        initial=child['original_output_identities'][stream]
        _ehn_keys(initial,_EHN_META_KEYS,'original created stream metadata differs')
        before=[initial[k] for k in _EHN_META_KEYS];_ehn_metadata(before,size=0)
        _ehn_need(before[:6]==meta[:6] and _ehn_stat.S_IMODE(meta[2])==0o600,
            'created output inode/owner/mode changed')
    _ehn_need(raws['child_stderr']==b'' and result['state']=='ORIGINAL_HOST_CHILD_JOINED'
        and result['phase']==_EHN_PHASE and type(result['pid']) is int and result['pid']==child['pid']
        and type(result['returncode']) is int and result['returncode']==0
        and result['automatic_retry'] is False
        and _ehn_equal(result['stdout'],roles['child_stdout'])
        and _ehn_equal(result['stderr'],roles['child_stderr']),'actual original child result differs')
    return _ehn_strict(raws['child_stdout'],65536)


def _ehn_parent_rows(rows,path):
    _ehn_need(type(rows) is list and 1<=len(rows)<=24,'bounded complete parent sequence required')
    expected=list(reversed([str(p) for p in _EhnPath(path).parents]))
    _ehn_need([r['path'] for r in rows]==expected,'parent sequence differs from actual source path')
    for row in rows:
        _ehn_keys(row,('path','metadata'),'parent observation shape differs')
        _ehn_metadata(row['metadata'],directory=True)


def _ehn_digest(raw):
    return _ehn_bare(raw)['sha256']


def _ehn_names_wire(value):
    return (_ehn_json.dumps(value,ensure_ascii=False,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode('utf-8','strict')


def _ehn_names_decode(value):
    _ehn_need(type(value) is dict and set(value)=={'schema','encoding','count','decoded','rows'}
        and value['schema']=='hepta.directory-name-prefix-table.v1'
        and value['encoding']=='unicode-prefix-length-and-suffix',
        'fixed parent name data encoding required')
    _ehn_need(type(value['count']) is int and 0<=value['count']<=4096
        and type(value['rows']) is list and len(value['rows'])==value['count'],
        'original name count bound exceeded')
    pin=value['decoded']
    _ehn_need(type(pin) is dict and set(pin)=={'bytes','sha256'} and type(pin['bytes']) is int
        and 3<=pin['bytes']<=524288 and type(pin['sha256']) is str
        and _ehn_re.fullmatch('[0-9a-f]{64}',pin['sha256']),
        'bounded full decoded name descriptor required')
    _ehn_need(len(_ehn_names_wire(value))<=65536,'prefix data exceeds original serialized field bound')
    names=[];previous='';decoded_charge=3
    for row in value['rows']:
        _ehn_need(type(row) is list and len(row)==2 and type(row[0]) is int
            and 0<=row[0]<=len(previous) and type(row[1]) is str,
            'typed bounded prefix/suffix row required')
        name=previous[:row[0]]+row[1]
        _ehn_need(name and '/' not in name and '\x00' not in name and name not in ('.','..')
            and (not names or previous<name),'complete names must be strict sorted unique basenames')
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        _ehn_need(row[0]==common,'prefix length must be canonical maximal common prefix')
        decoded_charge+=len(_ehn_names_wire(name))-1+(1 if names else 0)
        _ehn_need(decoded_charge<=pin['bytes']<=524288,'decoded names exceed bounded original bytes')
        names.append(name);previous=name
    raw=_ehn_names_wire(names)
    _ehn_need(len(raw)==pin['bytes'] and _ehn_digest(raw)==pin['sha256'],'complete decoded names bytes/SHA differ')
    return names


def _ehn_names_encode(names):
    _ehn_need(type(names) is list and len(names)<=4096 and all(type(x) is str for x in names)
        and names==sorted(set(names)),'original complete name count/order differs')
    raw=_ehn_names_wire(names)
    _ehn_need(len(raw)<=524288,'complete decoded parent names exceed the shared metadata pool')
    rows=[];previous=''
    for name in names:
        common=0
        while common<min(len(previous),len(name)) and previous[common]==name[common]:common+=1
        rows.append([common,name[common:]]);previous=name
    value={'schema':'hepta.directory-name-prefix-table.v1','encoding':'unicode-prefix-length-and-suffix',
        'count':len(names),'decoded':{'bytes':len(raw),'sha256':_ehn_digest(raw)},'rows':rows}
    _ehn_need(len(_ehn_names_wire(value))<=65536 and _ehn_names_decode(value)==names,
        'lossless complete prefix data exceeds original serialized field bound')
    return value


def _ehn_sources(roles,raws):
    for name,pin in _EHN_SOURCE_PINS.items():
        _ehn_need(_ehn_equal(roles[name],pin),'independent fixed source identity differs: '+name)
    _ehn_need(_ehn_equal(_ehn_bare(raws['bootstrap_source']),_EHN_BOOTSTRAP_PIN)
        and _ehn_equal(_ehn_bare(raws['controller_request']),_EHN_REQUEST_PIN),
        'complete fixed bootstrap or request body differs')
    manifest=_ehn_strict(raws['source_manifest'],65536)
    expected={'schema':'hepta.native-guard.retained-failed-native-history-owned-source.v1',
        'target_root':_EHN_SOURCE,'files':[{'path':_EhnPath(_EHN_SOURCE_PINS[r]['path']).name,
          **{k:_EHN_SOURCE_PINS[r][k] for k in ('bytes','sha256')}}
          for r in ('auditor_source','caller_source')]}
    _ehn_need(_ehn_equal(manifest,expected),'actual complete three-file source namespace differs')
    return sorted([*_EHN_SOURCE_PINS.values(),roles['bootstrap_source']],key=lambda r:r['path'])


def _ehn_controller(binding,roles,raws):
    request=_ehn_strict(raws['controller_request'],131072)
    expected={'host':'pocket4','executable':'/usr/bin/python3','args':['-I','-B','-c',_EHN_BOOTSTRAP_HEADER],
        'cwd':'/home/alex','stdin':raws['bootstrap_source'].decode('utf-8','strict'),
        'idempotency_key':'root-1ad3-retained6077-independent-host-audit01-20261105'}
    _ehn_need(_ehn_equal(request,expected),'actual source-bound request/stdin differs')
    start=_ehn_native(raws['controller_start']);status=_ehn_native(raws['controller_status'])
    read=_ehn_native(raws['controller_read']);job=start['job'];job_id=binding['controller_job_id']
    _ehn_need(type(job_id) is str and _ehn_re.fullmatch('[0-9a-f]+-[0-9a-f]+-[0-9a-f]+',job_id),
        'fixed actual native controller job ID required')
    _ehn_flags(start,true=('audit_recorded',),false=('local_record_pending','reused'))
    _ehn_need(start['launch']['ok'] is True and job['id']==job_id
        and job['launch_state']=='launched' and job['launch_error'] is None and job['env_keys']==[],
        'controller actual launch identity differs')
    for key in ('host','executable','args','cwd','idempotency_key'):
        _ehn_need(_ehn_equal(job[key],request[key]),'actual controller source/action differs: '+key)
    _ehn_need(status['job_id']==job_id and status['state']=='succeeded'
        and type(status['exit_code']) is int and status['exit_code']==0
        and read['job_id']==job_id,'same actual controller successful terminal required')
    _ehn_flags(status,true=('audit_recorded','output_complete','output_durable','terminal_publication_confirmed'),
        false=('automatic_retry','cancelled','timed_out'))
    _ehn_need(type(status['terminal_publication_protocol']) is int
        and status['terminal_publication_protocol']==1,'actual terminal protocol differs')
    _ehn_flags(read,true=('audit_recorded',))
    for stream in ('stdout','stderr'):
        row=read[stream];raw=raws['controller_'+stream]
        _ehn_need(type(row) is dict and type(row['bytes_hex']) is str
            and row['bytes_hex']==raw.hex() and row['eof'] is True,'complete controller stream differs')
        for key,want in (('offset',0),('next_offset',len(raw)),('size',len(raw))):
            _ehn_need(type(row[key]) is int and row[key]==want,'controller stream offset/EOF differs')
        _ehn_need(_ehn_equal(status['log_bytes'][stream],{'seen':len(raw),'stored':len(raw)})
            and status['log_errors'][stream] is None and status['log_synced'][stream] is True
            and status['log_truncated'][stream] is False,'controller complete/durable stream differs')
    _ehn_need(raws['controller_stderr']==b'' and len(raws['controller_stdout'])<=65536,
        'successful fixed caller bounded stdout and empty stderr required')
    final=_ehn_strict(raws['controller_stdout'],65536)
    _ehn_need(final['schema']=='hepta.native-guard.retained-failed-native-history-owned-caller-summary.v1'
        and final['state']=='OWNED_RETAINED_BRANCH_AUDITOR_JOINED_ALL_ORIGINALS_RETAINED_AND_CALLER_FDS_CLOSED'
        and _ehn_equal(final['caller_result'],roles['caller_result']),
        'actual caller final output does not bind its complete result')
    _ehn_flags(final,true=('external_controller_originals_still_required',),
        false=('automatic_retry','case_pass'),zero=('signals_sent','phone_calls'))
    _ehn_need(type(final['actual_child_starts']) is int and final['actual_child_starts']==1,
        'exactly one actual owned child required')
    return final


def _ehn_stage(roles,raws,source_observations):
    intent=_ehn_strict(raws['stage_intent'],65536)
    stage=_ehn_strict(raws['stage_result'],65536)
    returned=_ehn_strict(raws['stage_returned'],65536)
    source_rows={_EhnPath(_EHN_SOURCE_PINS[k]['path']).name:_EHN_SOURCE_PINS[k]
        for k in ('auditor_source','caller_source','source_manifest')}
    expected_intent={'schema':'hepta.diag6077.host-source-stage-intent.v1',
        'bootstrap':roles['bootstrap_source'],'sources':source_rows,
        'owned_argv':_EHN_OWNED_ARGV,'audit_out':_EHN_AUDIT_OUT,'owned_out':_EHN_CALLER_OUT,
        'original_close_calls':0,'original_main_calls':0,'phone_calls':0,
        'no_automatic_retry':True,'one_owned_auditor_child_only':True}
    _ehn_need(_ehn_equal(intent,expected_intent),'actual fixed bootstrap intent differs')
    _ehn_keys(stage,('schema','state','sources','source_directory_metadata','source_closed_set','phone_calls','case_credit'),
        'complete actual source-stage result differs')
    _ehn_need(stage['schema']=='hepta.diag6077.host-source-stage-result.v1'
        and stage['state']=='COMPLETE_PLAINTEXT_SOURCES_STAGED_AUDIT_NOT_YET_STARTED'
        and stage['source_closed_set']==sorted(source_rows),'stage scope or closed-set differs')
    _ehn_flags(stage,zero=('phone_calls','case_credit'))
    _ehn_keys(stage['sources'],source_rows,'source-stage exact three plaintext rows required')
    for name,descriptor in source_rows.items():
        _ehn_full4(stage['sources'][name],descriptor)
        observed=(source_observations['source_manifest'] if name=='SOURCE-MANIFEST.json'
                  else source_observations['sources'][name])
        _ehn_need(_ehn_equal(stage['sources'][name]['metadata'],observed['metadata']),
            'source-stage and owned source full9 differ')
        _ehn_need(_ehn_equal(stage['source_directory_metadata'],observed['parents'][-1]['metadata']),
            'complete source directory changed across actual stage and owned audit')
    _ehn_metadata(stage['source_directory_metadata'],directory=True)
    _ehn_keys(returned,('schema','state','actual_owned_wrapper_entered','actual_owned_wrapper_returned',
        'caller_result','source_directory_metadata','phone_calls','new_case_or_nonce','component_qualified',
        'external_controller_full_termination_still_required'),'complete bootstrap returned state required')
    _ehn_need(returned['schema']=='hepta.diag6077.host-bootstrap-return.v1'
        and returned['state']=='OWNED_WRAPPER_RETURNED_SOURCE_BOOKENDS_COMPLETE'
        and _ehn_equal(returned['source_directory_metadata'],stage['source_directory_metadata']),
        'bootstrap post-owned return/bookend differs')
    _ehn_full4(returned['caller_result'],roles['caller_result'])
    _ehn_flags(returned,true=('actual_owned_wrapper_entered','actual_owned_wrapper_returned',
        'external_controller_full_termination_still_required'),false=('new_case_or_nonce','component_qualified'),
        zero=('phone_calls',))
    return {'stage_intent':roles['stage_intent'],'stage_result':roles['stage_result'],
        'stage_returned':roles['stage_returned'],'bootstrap_source':roles['bootstrap_source']}


def _ehn_caller(roles,raws,audits,controller_final):
    caller=_ehn_strict(raws['caller_result'],65536)
    sources=_ehn_strict(raws['caller_sources'],262144)
    _ehn_need(caller['schema']=='hepta.native-guard.retained-failed-native-history-owned-caller.v1'
        and caller['state']=='FIXED_RETAINED_BRANCH_AUDITOR_JOINED_AND_COMPLETE_OUTPUTS_RECHECKED'
        and _ehn_equal(caller['source_manifest'],roles['source_manifest'])
        and _ehn_equal(caller['sources'],{'audit_existing_closure.py':roles['auditor_source'],
            'run_retained_failed_native_history_owned_once.py':roles['caller_source']})
        and _ehn_equal(caller['argv'],_EHN_ARGV) and caller['phase']==_EHN_PHASE,
        'actual caller source/action fields differ')
    for key,role in (('child','child_identity'),('result','child_result'),('joined','child_result'),
                     ('output_capture','child_capture'),('stdout','child_stdout'),('stderr','child_stderr'),
                     ('source_observations','caller_sources')):
        _ehn_need(_ehn_equal(caller[key],roles[role]),'caller source/action original differs: '+key)
    _ehn_flags(caller,true=('no_parent_all_time_full9_stability_claim','controller_authority_still_required',
        'nonce_reuse_forbidden','old_sender_parent_unknown_not_rewritten'),
        false=('new_nonce_or_lease','component_qualified','business_qualified','automatic_retry','canonical_chain_member'),
        zero=('phone_calls','signals_sent'))
    _ehn_need(caller['retained_branch_nonce']==_EHN_NONCE and caller['native_status']=='provider_failed'
        and type(caller['actual_native_calls']) is int and caller['actual_native_calls']==1,
        'retained failed branch was relabelled')
    _ehn_need(_ehn_equal(caller['cleanup'],{'stream_cleanup_errors':[],'host_children':[]})
        and _ehn_equal(controller_final['owned_host_cleanup'],caller['cleanup']),
        'actual owned caller cleanup differs')
    for key,want in (('physical_read_limit',16777216),('metadata_limit',524288),('stream_pool_limit',262144)):
        _ehn_need(type(caller[key]) is int and caller[key]==want,'caller fixed bound differs')
    for key in ('read_bytes','capture_read_bytes_reserved','physical_read_total_upper','metadata_bytes','stream_write_bytes_reserved',
                'parent_names_decoded_bytes','metadata_total_charged_bytes'):
        _ehn_need(type(controller_final[key]) is int and controller_final[key]>=0,'caller resource counter type differs')
    _ehn_need(controller_final['read_bytes']+controller_final['capture_read_bytes_reserved']+controller_final['parent_names_decoded_bytes']==
        controller_final['physical_read_total_upper']<=16777216
        and controller_final['capture_read_bytes_reserved']<=262148
        and controller_final['metadata_bytes']+controller_final['parent_names_decoded_bytes']==
        controller_final['metadata_total_charged_bytes']<=524288
        and controller_final['stream_write_bytes_reserved']<=262144,
        'caller actual read/write bounds exceeded')
    _ehn_keys(sources,('schema','source_manifest','sources','parent_transition','audit_outputs','audit_directories',
        'self_report_is_not_source_authority'),'complete caller source observations differ')
    _ehn_need(sources['schema']=='hepta.native-guard.retained-failed-native-history-caller-sources.v1'
        and sources['self_report_is_not_source_authority'] is True,'source observation scope differs')
    _ehn_keys(sources['sources'],('audit_existing_closure.py','run_retained_failed_native_history_owned_once.py'),
        'caller did not retain both source observations')
    for record,role in ((sources['source_manifest'],'source_manifest'),
        (sources['sources']['audit_existing_closure.py'],'auditor_source'),
        (sources['sources']['run_retained_failed_native_history_owned_once.py'],'caller_source')):
        _ehn_keys(record,('path','bytes','sha256','metadata','parents'),'actual source read shape differs')
        _ehn_full4({k:record[k] for k in ('path','bytes','sha256','metadata')},roles[role])
        _ehn_parent_rows(record['parents'],record['path'])
    transition=sources['parent_transition']
    _ehn_keys(transition,('schema','before','after','allowed_created_directory',
        'ordinary_ancestors_full9_equal','base_first5_equal','base_all_time_full9_stable_claim',
        'only_declared_name_added'),'caller parent transition shape differs')
    _ehn_need(transition['schema']=='hepta.native-guard.retained-failed-native-history-caller-parent-transition.v1'
        and transition['allowed_created_directory']==_EHN_AUDIT_OUT,'caller owned directory addition differs')
    _ehn_flags(transition,true=('ordinary_ancestors_full9_equal','base_first5_equal','only_declared_name_added'),
        false=('base_all_time_full9_stable_claim',))
    before=transition['before'];after=transition['after'];decoded_names=[]
    for row,role in ((before,'parent_names_before'),(after,'parent_names_after')):
        _ehn_keys(row,('parents','base_names'),'BASE observation shape differs')
        _ehn_parent_rows(row['parents'],roles['caller_source']['path'])
        names=_ehn_names_decode(row['base_names'])
        _ehn_need(raws[role]==_ehn_names_wire(names),
            'explicit derived carrier differs from complete actual parent names')
        decoded_names.append(names)
    for left,right in zip(before['parents'],after['parents']):
        _ehn_need(left['path']==right['path'],'parent path changed')
        _ehn_need(_ehn_equal(left['metadata'][:5],right['metadata'][:5]) if left['path']==_EHN_BASE
            else _ehn_equal(left,right),'unapproved source ancestor changed')
    name=_EhnPath(_EHN_AUDIT_OUT).name
    _ehn_need(name not in decoded_names[0] and decoded_names[1]==sorted(decoded_names[0]+[name]),
        'undeclared BASE additions or removals occurred')
    decoded_charge=len(raws['parent_names_before'])+len(raws['parent_names_after'])
    _ehn_need(type(caller['parent_names_decoded_bytes']) is int
        and caller['parent_names_decoded_bytes']==controller_final['parent_names_decoded_bytes']==decoded_charge
        and caller['parent_names_byte_charge_is_canonical_expanded_data_not_kernel_dirent_bytes'] is True
        and controller_final['parent_names_byte_charge_is_canonical_expanded_data_not_kernel_dirent_bytes'] is True,
        'complete expanded parent names were not charged to the same caller pools')
    _ehn_keys(sources['audit_outputs'],audits,'all twenty-five actual audit observations required')
    _ehn_keys(caller['audit_outputs'],audits,'caller complete audit output map required')
    _ehn_keys(controller_final['auditor_originals'],audits,'controller final complete audit output map required')
    directory_names={_EHN_AUDIT_OUT:sorted([n for n in audits if '/' not in n]+['derived','sender-originals']),
        _EHN_AUDIT_OUT+'/derived':sorted(n.split('/',1)[1] for n in audits if n.startswith('derived/')),
        _EHN_AUDIT_OUT+'/sender-originals':sorted(n.split('/',1)[1] for n in audits if n.startswith('sender-originals/'))}
    _ehn_keys(sources['audit_directories'],directory_names,'complete audit directories required')
    for path,names in directory_names.items():
        row=sources['audit_directories'][path]
        _ehn_keys(row,('path','metadata','names'),'audit directory observation shape differs')
        _ehn_metadata(row['metadata'],directory=True)
        _ehn_need(row['path']==path and row['names']==names
            and row['metadata'][3:5]==[1000,1000] and _ehn_stat.S_IMODE(row['metadata'][2])==0o700,
            'actual audit directory closed-set or identity differs')
    for filename,descriptor in audits.items():
        observed=sources['audit_outputs'][filename]
        _ehn_keys(observed,('path','bytes','sha256','metadata','parents'),'caller audit output observation differs')
        _ehn_full4({k:observed[k] for k in ('path','bytes','sha256','metadata')},descriptor)
        _ehn_parent_rows(observed['parents'],observed['path'])
        _ehn_need(_ehn_equal(caller['audit_outputs'][filename],descriptor)
            and _ehn_equal(controller_final['auditor_originals'][filename],descriptor),
            'caller final and actual audit output disagree')
        for row in observed['parents']:
            if row['path'] in sources['audit_directories']:
                _ehn_need(_ehn_equal(row['metadata'],sources['audit_directories'][row['path']]['metadata']),
                    'audit parent full9 differs from complete closed directory observation')
    expected_members=sorted((roles[r] for r in ('caller_sources','caller_result','child_intent','child_identity',
        'child_result','child_capture','child_stdout','child_stderr')),key=lambda row:row['path'])
    _ehn_need(_ehn_equal(controller_final['originals'],expected_members),'caller exact eight-file closure differs')
    return sources


def _ehn_audit(roles,raws,audits,audit_raws,sources,child_summary,budget_check):
    """Verify actual delegated host evidence; do not re-read its deep input domain."""
    closed=_ehn_strict(raws['original_closure'],65536)
    _ehn_need(_ehn_equal(_ehn_bare(raws['original_closure']),_EHN_CLOSURE_PIN)
        and len(closed)==49 and audit_raws['RECOMPUTED-EXPECTED-CLOSURE.json']==raws['original_closure'],
        'complete original49 fields must remain byte-identical')
    _ehn_need(closed['schema']=='hepta.native-guard.original-closure.v1'
        and closed['state']=='ORIGINAL_NATIVE_COMPONENT_FAILED_CLOSED'
        and closed['nonce']==_EHN_NONCE and closed['boot_id']==_EHN_BOOT
        and closed['native_status']=='provider_failed' and type(closed['actual_native_calls']) is int
        and closed['actual_native_calls']==1 and closed['package_sha256']==_EHN_PACKAGE_PIN['sha256']
        and closed['combination_sha256']==_EHN_COMBINATION and closed['closure_source_sha256']==_EHN_SOURCE_PINS['original_closer_source']['sha256'],
        'fixed retained failed native identity differs')
    _ehn_flags(closed,true=('closed','all_actual_r6_calls_verified','all_prior_originals_preserved',
        'global_ledger_delta_verified','independent_role_and_endpoint_absence_verified',
        'native_hash_chain_and_terminal_verified','original_sender_and_draft_restoration_verified'),
        false=('boundary_published_here','business_qualified','component_qualified','four_role_qualification',
        'automatic_replay','old_retirement_current_equality_claimed','original_retirement_rewritten','two_original_r6_calls_verified'),
        zero=('commands_executed','model_requests','phone_calls','unknown_effects'))
    _ehn_need(_ehn_equal(_ehn_bare(raws['original_plan']),_EHN_PLAN_PIN)
        and _ehn_equal(_ehn_bare(raws['original_package']),_EHN_PACKAGE_PIN),
        'fixed original plan or package body differs')
    plan=_ehn_strict(raws['original_plan'],65536);package=_ehn_strict(raws['original_package'],65536)
    _ehn_need(plan['schema']=='hepta.native-guard.closure-plan.v1' and plan['label']==_EHN_LABEL
        and _ehn_equal(plan['package'],roles['original_package'])
        and _ehn_equal(plan['archive'],closed['archive']) and _ehn_equal(closed['archive'],_EHN_ARCHIVE)
        and plan['capture_sha256']==_EHN_CAPTURE_PIN['sha256']
        and _ehn_equal(closed['capture'],_EHN_CAPTURE_PIN),'original plan/capture/closure crosslink differs')
    _ehn_need(package['schema']=='hepta.native-guard.adapter-package.v1'
        and package['state']=='HOST_REVIEWED_NOT_PHONE_QUALIFIED' and len(package['files'])==32,
        'original complete source manifest differs')
    expected_intent={'schema':'hepta.existing-failed-closure.independent-host-intent.v1',
        'driver':roles['auditor_source'],'original_close_source':roles['original_closer_source'],
        'original_plan':roles['original_plan'],'original_closure':roles['original_closure'],
        'old_snapshot_resource_anchor':_EHN_OLD_BASE+'/closure/snapshot','new_derived_output':_EHN_AUDIT_OUT,
        'original_main_calls':0,'original_close_calls':0,'phone_calls':0,'snapshot_calls':0,
        'native_dispatches':0,'boundary_publications':0,'automatic_retry':False,'case_pass':False,
        'old_mac_sender_capture_unknown_preserved':True}
    _ehn_need(_ehn_equal(_ehn_strict(audit_raws['AUDIT-INTENT.json'],65536),expected_intent),
        'actual fixed original pure invocation intent differs')
    for name,pin in _EHN_AUDIT_PINS.items():
        budget_check()
        _ehn_need(_ehn_equal(_ehn_bare(audit_raws[name]),pin),'complete expected audit output differs: '+name)
    _ehn_need(audit_raws['RECOMPUTED-NATIVE-AUDIT.json']==_ehn_encode(closed['independent_native_audit'])
        and _ehn_equal(_ehn_bare(audit_raws['RECOMPUTED-AFTER-INVENTORY.json']),closed['inventory']),
        'actual derived audit or whole inventory differs from complete old closure')
    proof=_ehn_strict(audit_raws['BYTE-EQUALITY.json'],262144)
    flags={'schema':'hepta.existing-failed-closure.independent-host-byte-equality.v1',
        'state':'EXISTING_FAILED_CLOSURE_FULL_OBJECT_RECOMPUTED_BYTE_EQUAL',
        'driver':roles['auditor_source'],'original_close_source':roles['original_closer_source'],
        'original_plan':roles['original_plan'],'original_closure':roles['original_closure'],
        'historical_original_host_inputs_exact':True,'new_host_derivation_only':True,
        'original_main_calls':0,'original_close_calls':0,'source_modules_replaced_or_relabelled':False,
        'original_host_metadata_replaced':False,'complete_object_fields_deleted_or_normalized':False,
        'phone_calls':0,'native_dispatches':0,'sender_runs':0,'snapshot_calls':0,'boundary_publications':0,
        'signals':0,'new_native_closure':False,'eligible_for_publication':False,'fresh_phone_clearance':False,
        'component_qualified':False,'case_pass':False,'automatic_retry':False,
        'old_mac_sender_capture_unknown_preserved':True,'owned_read_fd_bookend_complete':True,
        'pure_validator_counted_scope':'All original9025 close validators and unchanged full closed-object expression',
        'recomputed':audits['RECOMPUTED-EXPECTED-CLOSURE.json'],'closed_object_expression':_EHN_CLOSED_EXPRESSION}
    _ehn_keys(proof,(*flags,'elapsed_seconds','driver_original_observations'),
        'complete actual full-byte-equality proof shape differs')
    _ehn_need(_ehn_equal({k:proof[k] for k in flags},flags),'actual proof/source/full-object scope differs')
    _ehn_need(type(proof['elapsed_seconds']) in (int,float) and _ehn_math.isfinite(proof['elapsed_seconds'])
        and 0<=proof['elapsed_seconds']<=100,'actual owned audit elapsed time differs')
    expected_stdout={'state':proof['state'],'receipt':audits['BYTE-EQUALITY.json'],
        'phone_calls':0,'new_native_closure':False,'case_pass':False}
    _ehn_need(_ehn_equal(child_summary,expected_stdout),'complete auditor stdout does not bind the proof')
    rows=proof['driver_original_observations']
    _ehn_need(type(rows) is dict and len(rows)==160,'complete actual Guard160 table required')
    bare={}
    for path,row in rows.items():
        budget_check();_ehn_keys(row,('bytes','sha256','metadata'),'actual Guard row shape differs')
        descriptor=_ehn_descriptor({'path':path,'bytes':row['bytes'],'sha256':row['sha256']})
        _ehn_metadata(row['metadata'],size=descriptor['bytes'])
        bare[path]={k:descriptor[k] for k in ('bytes','sha256')}
    _ehn_need(_ehn_digest(_ehn_encode(bare))==_EHN_GUARD_MAP_SHA256
        and sum(r['bytes'] for r in bare.values())==5373187,
        'complete fixed Guard160 paths/bytes/source map differs')
    original=closed['original_host_inputs']
    _ehn_need(type(original) is dict and len(original)==137
        and sum(r['bytes'] for r in original.values())==4901803,'complete original137 input table differs')
    for path,row in original.items():
        budget_check();_ehn_keys(row,('bytes','sha256','metadata'),'original137 row shape differs')
        _ehn_need(path in rows and _ehn_equal(row,rows[path]),
            'actual host readset did not preserve complete original full9: '+path)
    for role in ('auditor_source','original_closer_source','original_closure','original_plan','original_package'):
        row=roles[role]
        _ehn_need(row['path'] in rows and _ehn_equal(bare[row['path']],{k:row[k] for k in ('bytes','sha256')}),
            'actual Guard omitted fixed source/input role: '+role)
    _ehn_need(_ehn_equal(rows[roles['auditor_source']['path']]['metadata'],
        sources['sources']['audit_existing_closure.py']['metadata']),
        'actual auditor source full9 differs from owned caller observation')
    for row in package['files']:
        budget_check();_ehn_keys(row,('path','bytes','sha256'),'source manifest row shape differs')
        path=_EHN_OLD_BASE+'/material/tree/package/'+row['path']
        _ehn_need(path in original and _ehn_equal({k:original[path][k] for k in ('bytes','sha256')},
            {k:row[k] for k in ('bytes','sha256')}),'original source32 complete table linkage differs')
    _ehn_need(_ehn_equal(rows[closed['archive']['path']]['bytes'],closed['archive']['bytes'])
        and rows[closed['archive']['path']]['sha256']==closed['archive']['sha256'],
        'actual host whole archive read is absent from the Guard')
    readset={'schema':'hepta.native-guard.retained-failed-native-delegated-host-readset.v1',
        'proof':audits['BYTE-EQUALITY.json'],'guard_original_paths':160,'guard_path_bytes':5373187,
        'guard_bare_map_sha256':_EHN_GUARD_MAP_SHA256,'original_host_inputs':137,
        'original_host_input_path_bytes':4901803,'all_original137_full9_equal':True,
        'actual_host_archive':closed['archive'],'archive_regular_members':278,'capture_rows':277,
        'source_action_proves_original_validators_and_whole_closure_recomputation':True,
        'deep_input_bodies_reread_by_this_pure_consumer':False,
        'readset_descriptors_are_not_claimed_to_be_raw_bodies':True}
    return closed,proof,readset


def verify_epoch_retained_native_history(input_raw, *, read_pinned, budget_check):
    """Verify fixed source/action through explicitly bound physical data carriers."""
    binding=EPOCH_RETAINED_NATIVE_HISTORY_AUTHORITY_BINDING
    _ehn_need(type(binding) is dict,'actual externally reviewed source/action binding is not installed')
    _ehn_keys(binding,('schema','input','authority','roles','audit_outputs','controller_job_id','carriers'),
        'fixed retained history source binding shape differs')
    _ehn_need(binding['schema']=='hepta.native-guard.retained-failed-native-history-source-binding.v2'
        and globals().get('__actual_context__') in ('phone','mac','p4')
        and callable(read_pinned) and callable(budget_check),
        'explicit reviewed context and original callbacks required')
    budget_check();_ehn_descriptor(binding['input']);_ehn_descriptor(binding['authority'])
    _ehn_need(binding['input']['path']==_EHN_CARRIER_ROOT+'/INPUT.original.json'
        and binding['authority']['path']==_EHN_CARRIER_ROOT+'/AUTHORITY.original.json',
        'fixed physical input and authority carrier paths required')
    _ehn_need(_ehn_equal(_ehn_bare(input_raw),{k:binding['input'][k] for k in ('bytes','sha256')}),
        'actual fixed history input body differs')
    value=_ehn_strict(input_raw,65536)
    _ehn_keys(value,EPOCH_RETAINED_NATIVE_HISTORY_INPUT_FIELDS,'retained history input exact shape differs')
    _ehn_need(value['schema']=='hepta.native-guard.epoch-retained-failed-native-history-input.v2'
        and value['epoch_id']=='legacy902-active01' and value['label']==_EHN_LABEL
        and value['nonce']==_EHN_NONCE and value['boot_id']==_EHN_BOOT,
        'fixed retained branch epoch/identity differs')
    roles=_ehn_keys(binding['roles'],EPOCH_RETAINED_NATIVE_HISTORY_ROLES,'fixed complete27 source/action roles required')
    audits=_ehn_keys(binding['audit_outputs'],(*_EHN_AUDIT_PINS,'BYTE-EQUALITY.json'),
        'fixed complete25 audit output roles required')
    declared={}
    def declare(row):
        _ehn_descriptor(row);path=row['path']
        _ehn_need(path not in declared or _ehn_equal(declared[path],row),'conflicting duplicate original identity')
        declared[path]=row
    role_paths=[]
    for row in roles.values():declare(row);role_paths.append(row['path'])
    _ehn_need(len(set(role_paths))==len(role_paths),'distinct source/action roles must have distinct original paths')
    for name,row in audits.items():
        declare(row);_ehn_need(row['path']==_EHN_AUDIT_OUT+'/'+name,'fixed audit output path differs')
        if name in _EHN_AUDIT_PINS:
            _ehn_need(_ehn_equal({k:row[k] for k in ('bytes','sha256')},_EHN_AUDIT_PINS[name]),
                'fixed expected complete audit body pin differs')
        else:_ehn_need(0<row['bytes']<=262144,'bounded actual byte-equality proof required')
    for key,path in _EHN_FIXED_ROLE_PATHS.items():
        _ehn_need(roles[key]['path']==path,'fixed source/action namespace differs: '+key)
    for role,pin in (('original_closure',_EHN_CLOSURE_PIN),('original_plan',_EHN_PLAN_PIN),('original_package',_EHN_PACKAGE_PIN)):
        _ehn_need(_ehn_equal({k:roles[role][k] for k in ('bytes','sha256')},pin),'fixed old input differs: '+role)
    pairs=binding['carriers']
    _ehn_need(type(pairs) is list and len(pairs)==len(declared)==52,
        'complete externally bound52 origin/carrier pairs required')
    carriers={};physical={};origin_order=[]
    for pair in pairs:
        budget_check();_ehn_keys(pair,('origin','carrier'),'exact origin/carrier pair required')
        origin=_ehn_descriptor(pair['origin']);carrier=_ehn_descriptor(pair['carrier'])
        path=origin['path'];origin_order.append(path)
        _ehn_need(path in declared and _ehn_equal(declared[path],origin) and path not in carriers,
            'carrier pair selected an unbound or duplicate semantic origin')
        _ehn_need(carrier['path'].startswith(_EHN_CARRIER_ROOT+'/originals/')
            and carrier['path'] not in physical and carrier['path'] not in declared
            and _ehn_equal({k:origin[k] for k in ('bytes','sha256')},
                {k:carrier[k] for k in ('bytes','sha256')}),
            'physical carrier must be distinct and preserve complete origin bytes/SHA')
        carriers[path]=carrier;physical[carrier['path']]=carrier
    _ehn_need(origin_order==sorted(declared) and set(carriers)==set(declared),
        'externally fixed origin/carrier map must be complete and canonical')
    _ehn_need(_ehn_equal(value['originals'],sorted(physical.values(),key=lambda r:r['path']))
        and _ehn_equal(value['authority'],binding['authority'])
        and _ehn_equal(value['original_closure'],roles['original_closure']),
        'input selected unbound physical carriers, authority or semantic closure')
    origin_declared=dict(declared)
    for key in ('authority','input'):
        row=binding[key]
        _ehn_need(row['path'] not in declared and row['path'] not in physical,
            'packet carrier overlaps an original or another carrier')
        declare(row);carriers[row['path']]=row;physical[row['path']]=row
    used={};origin_used={};body_cache={};digest_bodies={}
    def get(row):
        budget_check();_ehn_descriptor(row);path=row['path']
        _ehn_need(path in declared and _ehn_equal(declared[path],row),'unlisted source/action original requested')
        carrier=carriers[path];carrier_path=carrier['path']
        if carrier_path not in body_cache:
            raw=read_pinned(carrier);budget_check()
            _ehn_need(type(raw) is bytes and _ehn_equal(_ehn_bare(raw),{k:row[k] for k in ('bytes','sha256')}),
                'complete physical carrier bytes differ from the fixed semantic original')
            if row['sha256'] in digest_bodies:
                _ehn_need(digest_bodies[row['sha256']]==raw,'same SHA reuse requires identical complete body')
            else:digest_bodies[row['sha256']]=raw
            body_cache[carrier_path]=raw;used[carrier_path]=carrier
        if path in origin_declared:origin_used[path]=row
        return body_cache[carrier_path]
    _ehn_need(get(binding['input'])==input_raw,'input carrier differs from supplied complete input')
    packet=_ehn_strict(get(binding['authority']),65536)
    _ehn_keys(packet,('schema','epoch_id','label','nonce','boot_id','roles','audit_outputs',
        'controller_job_id','original_closure','carriers'),'complete authority packet shape differs')
    expected={'schema':'hepta.native-guard.retained-failed-native-history-authority.v2',
        'epoch_id':'legacy902-active01','label':_EHN_LABEL,'nonce':_EHN_NONCE,'boot_id':_EHN_BOOT,
        'roles':roles,'audit_outputs':audits,'controller_job_id':binding['controller_job_id'],
        'original_closure':roles['original_closure'],'carriers':pairs}
    _ehn_need(_ehn_equal(packet,expected),'evidence packet cannot choose or authorize its own source/action or carriers')
    raw_roles={name:get(row) for name,row in roles.items()}
    audit_raws={name:get(row) for name,row in audits.items()}
    sources=_ehn_sources(roles,raw_roles)
    controller_final=_ehn_controller(binding,roles,raw_roles)
    child_summary=_ehn_child(roles,raw_roles)
    source_observations=_ehn_caller(roles,raw_roles,audits,controller_final)
    stage=_ehn_stage(roles,raw_roles,source_observations)
    closed,proof,readset=_ehn_audit(roles,raw_roles,audits,audit_raws,source_observations,child_summary,budget_check)
    budget_check();_ehn_need(set(used)==set(physical) and set(origin_used)==set(origin_declared),
        'complete actual callback carrier set and semantic origin set were not both consumed')
    authority={'schema':'hepta.native-guard.retained-failed-native-history-source-action-verification.v2',
        'state':'FIXED_SOURCE_INPUTS_OWNED_EXECUTION_AND_WHOLE_FAILED_CLOSURE_VERIFIED',
        'packet':value['authority'],'sources':sources,'stage':stage,'proof':audits['BYTE-EQUALITY.json'],
        'readset':readset,'trust_model':'TRUSTED_RETAINED_CONTROLLER_TOOL_RECEIPTS',
        'controller_receipt_authenticity_not_independently_cryptographically_reconstructed':True,
        'original_deep_host_read_domain_not_mislabelled_as_phone_callback_bodies':True,
        'origin_to_carrier':pairs,'semantic_origin_readset':sorted(origin_used.values(),key=lambda r:r['path']),
        'callback_used_are_physical_carriers':True,'carrier_metadata_is_not_original_P4_metadata':True}
    return {'schema':'hepta.native-guard.epoch-retained-failed-native-history-verification.v2',
        'state':'RETAINED_FAILED_NATIVE_HISTORY_REVERIFIED_BY_COMPLETE_OWNED_HOST_AUDIT',
        'input':_ehn_bare(input_raw),'closed':closed,'proof':proof,'authority':authority,
        'used':sorted(used.values(),key=lambda r:r['path']),
        'actual_native_calls':1,'native_status':'provider_failed','canonical_chain_member':False,
        'active_slot_count_contribution':0,'nonce_reuse_forbidden':True,'component_qualified':False,
        'business_qualified':False,'case_credit':0,'fresh_phone_clearance':False,'new_nonce_or_lease':False}

