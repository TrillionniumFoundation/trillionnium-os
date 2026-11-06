#!/usr/bin/env python3
"""Read one ended sender's host originals; no phone, process signal or replay.

All original XML, draft and request bodies are preserved only in a new P4
private archive. Public output contains hashes, schema and UI structure only.
"""
from pathlib import Path
import base64,collections,gzip,hashlib,json,os,stat,xml.etree.ElementTree as ET
SOURCE=Path('/home/alex/codex-hepta-natural-root-r10-neg01-fc33-bound02-root-v150')
DEST=Path('/home/alex/razr60-local-model-v150/fc33-neg01-bound02-sender-preservation01')
MAX_FILE=8*1024*1024
MAX_TOTAL=32*1024*1024
MAX_FILES=512
def need(v,s):
    if not v:raise ValueError(s)
def sha(b):return hashlib.sha256(b).hexdigest()
def enc(v):return (json.dumps(v,sort_keys=True,ensure_ascii=False,separators=(',',':'),allow_nan=False)+'\n').encode()
def full9(s):return [getattr(s,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
def strict(b):
    def pairs(rows):
        d={}
        for k,v in rows:need(k not in d,'duplicate JSON key');d[k]=v
        return d
    return json.loads(b,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))
def read(p):
    need(p.resolve(strict=True)==p and p.parent==SOURCE,'exact canonical sender file')
    fd=os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        a=os.fstat(fd);need(stat.S_ISREG(a.st_mode) and a.st_nlink==1 and a.st_uid==a.st_gid==1000 and 0<=a.st_size<=MAX_FILE,'bounded regular sender original')
        with os.fdopen(fd,'rb',closefd=False) as f:b=f.read(MAX_FILE+1)
        need(len(b)==a.st_size and full9(a)==full9(os.fstat(fd))==full9(p.lstat()),'complete original file bookend')
        return b,{'path':str(p),'bytes':len(b),'sha256':sha(b),'metadata':full9(a)}
    finally:os.close(fd)
def put(name,b):
    p=DEST/name;need(p.parent==DEST,'one private preservation namespace')
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'wb') as f:f.write(b);f.flush();os.fsync(f.fileno())
    return {'path':str(p),'bytes':len(b),'sha256':sha(b)}
def xml_summary(s):
    i=s.find('<?xml ')
    if i<0:
        i=s.find('<hierarchy')
    if i<0:return None
    raw=s[i:].strip().encode()
    try:tree=ET.fromstring(raw)
    except ET.ParseError:return {'xml_bytes':len(raw),'xml_sha256':sha(raw),'parse_error':True}
    nodes=list(tree.iter('node'));ids=collections.Counter(n.get('resource-id','') for n in nodes)
    selected=['org.trillionnium.owneropen:id/'+n for n in ('ui_prompt','ui_control_status','ui_send','ui_tools','ui_task_summary','ui_inspect','ui_details','ui_log','ui_reconnect')]
    selected+=['android:id/button1','android:id/button2','android:id/alertTitle']
    prompts=[n for n in nodes if n.get('resource-id')=='org.trillionnium.owneropen:id/ui_prompt']
    return {'xml_bytes':len(raw),'xml_sha256':sha(raw),'parse_error':False,'node_count':len(nodes),
        'packages':sorted({n.get('package','') for n in nodes}),'resource_id_counts':{k:ids[k] for k in selected},
        'button2_control_labels':[n.get('text') if n.get('text') in ('关闭','完成','返回','取消') else '[non-public-label]' for n in nodes if n.get('resource-id')=='android:id/button2'],
        'focused_resource_ids':[n.get('resource-id','') for n in nodes if n.get('focused')=='true'],
        'prompt_text_hashes':[{'utf8_bytes':len(n.get('text','').encode()),'utf8_sha256':sha(n.get('text','').encode())} for n in prompts],
        'complete_resource_ids':sorted(k for k in ids if k)}
def summaries(obj,at='$'):
    found=[]
    if type(obj) is str:
        r=xml_summary(obj)
        if r is not None:found.append({'json_location':at,**r})
    elif type(obj) is dict:
        for k,v in obj.items():
            if type(v) in (str,dict,list):found.extend(summaries(v,at+'.'+k))
    elif type(obj) is list:
        for i,v in enumerate(obj):
            if type(v) in (str,dict,list):found.extend(summaries(v,at+'['+str(i)+']'))
    return found

need(SOURCE.resolve(strict=True)==SOURCE,'canonical exact sender root')
before=SOURCE.lstat();need(stat.S_ISDIR(before.st_mode) and before.st_uid==before.st_gid==1000,'private sender root')
names=sorted(os.listdir(SOURCE));need(0<len(names)<=MAX_FILES and len(set(names))==len(names),'bounded complete sender names')
files={};public=[];xmls=[];total=0
for name in names:
    need(name not in ('.','..') and '/' not in name,'exact direct child leaf')
    b,row=read(SOURCE/name);total+=len(b);need(total<=MAX_TOTAL,'whole sender originals byte bound')
    files[name]={'descriptor':row,'base64':base64.b64encode(b).decode()};item={'name':name,**row}
    try:
        value=strict(b);item['json_type']=type(value).__name__
        if type(value) is dict:
            item['keys']=sorted(value)
            item['rc']=value.get('rc') if type(value.get('rc')) is int else None
            command=value.get('command',value.get('cmd'))
            if type(command) is str:
                item['command_sha256']=sha(command.encode())
                item['command_kind']='uiautomator_dump' if 'uiautomator dump ' in command else ('unicode_input' if 'UnicodeInput ' in command else ('input_tap' if command.startswith('input tap ') else 'other_original_command'))
            if name=='ACTOR-FAILURE.json':item['actor_failure']=value
            if name=='DRAFT-RESTORE-RESULT.json':item['draft_restore']={k:value[k] for k in ('state','restore_attempts','original_draft_submitted','utf8_sha256')}
        for summary in summaries(value):xmls.append({'file':name,'file_sha256':row['sha256'],'file_metadata':row['metadata'],**summary})
    except (ValueError,TypeError,UnicodeError):
        item['json_type']='non_JSON_original'
        try:
            summary=xml_summary(b.decode())
            if summary is not None:xmls.append({'file':name,'file_sha256':row['sha256'],'file_metadata':row['metadata'],'json_location':'raw_file',**summary})
        except UnicodeError:pass
    public.append(item)
need(names==sorted(os.listdir(SOURCE)) and full9(before)==full9(SOURCE.lstat()),'complete sender namespace changed during preservation')
for name,row in files.items():need(full9((SOURCE/name).lstat())==row['descriptor']['metadata'],'final original path changed')
need(DEST.parent.resolve(strict=True)==DEST.parent and not DEST.exists(),'create-only private archive destination')
DEST.mkdir(mode=0o700)
private={'schema':'hepta.fc33.neg01-bound02.sender-host-originals-private.v1','source_path':str(SOURCE),'source_metadata':full9(before),'names':names,'files':files,'private_UI_draft_request_originals_do_not_publish':True}
private_raw=enc(private);archive=gzip.compress(private_raw,mtime=0);archive_pin=put('ORIGINALS.PRIVATE.json.gz',archive)
send_names=['SEND.once.json','SEND.MONOTONIC-INTENT.json','SEND.result.json','SEND.unknown.json','SEND.MONOTONIC-WINDOW.json','SEND-NATIVE-LATENCY.json','COMPONENT-PREPARED-NO-SEND.json']
report={'schema':'hepta.fc33.neg01-bound02.sender-host-public-observation.v1','state':'EXISTING_HOST_ORIGINALS_PRIVATELY_PRESERVED_NOT_SCOPE_CLOSURE',
 'source_path':str(SOURCE),'source_metadata':full9(before),'original_file_count':len(files),'original_bytes':total,'original_private_archive':archive_pin,
 'original_uncompressed_archive':{'bytes':len(private_raw),'sha256':sha(private_raw)},'originals':public,
 'XML_structural_observations':sorted(xmls,key=lambda r:(r['file_metadata'][7],r['file'],r['json_location'])),
 'specific_sender_records_present':{n:n in names for n in send_names},'phone_calls':0,'process_signals':0,
 'private_UI_text_in_public_report':False,'native_zero_effect_proved_by_this_host_observation_alone':False,'scope_closure':False,'component_qualified':False,'business_qualified':False}
report_pin=put('PUBLIC-OBSERVATION.json',enc(report))
print(json.dumps({'state':report['state'],'report':report_pin,'private_archive':archive_pin,'original_file_count':len(files),'original_bytes':total,
 'xml_observation_count':len(xmls),'specific_sender_records_present':report['specific_sender_records_present'],'phone_calls':0},sort_keys=True))
