#!/usr/bin/env python3
"""Stage a one-use ordinary-App model-only request. No device or subprocess calls."""
import argparse,hashlib,json,os,secrets,stat,struct,time,uuid
from pathlib import Path

SOURCE_SHA='57b6fc209afc1387a0bce841cba8399736537dd5e8a2729875ec031ca93f0e7c'
PREFIX_SHA='ba6f7c4d4b6aca98b3fd6737a1ae6fed1bc8b554963777a3217e5c25d7db438e'
VARIABLE_SHA='895e4ef16d0940e96b2c1cc24ec97a3372cb2bfadf3519bd197461298c96a1a5'
def sha(data):return hashlib.sha256(data).hexdigest()
def read(path,maximum):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        before=os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<=before.st_size<=maximum:raise ValueError('bounded regular input required')
        data=stream.read(maximum+1);after=os.fstat(stream.fileno());current=os.lstat(path)
    identity=lambda s:(s.st_dev,s.st_ino,s.st_size,s.st_uid,s.st_mode,s.st_nlink,s.st_mtime_ns,s.st_ctime_ns)
    if len(data)!=before.st_size or identity(before)!=identity(after) or identity(before)!=identity(current):raise ValueError('input changed during read')
    return data
def pairs(items):
    out={}
    for key,value in items:
        if key in out:raise ValueError('duplicate JSON key')
        out[key]=value
    return out
def obj(data):
    value=json.loads(data.decode('utf-8'),object_pairs_hook=pairs,parse_constant=lambda _:(_ for _ in ()).throw(ValueError('nonfinite JSON')))
    if type(value) is not dict:raise ValueError('one JSON object required')
    return value
def source_text(value,maximum):
    if type(value) is not str or not value or len(value.encode())>maximum or '\0' in value:raise ValueError('bounded nonempty owner/history required')
    if any(t in value for t in ('<img>','</img>','<audio>','</audio>','<image_placeholder>','<|im_start|>','<|im_end|>')):raise ValueError('reserved media/role token in owner/history')
def equal(value,key,expected):
    actual=value.get(key)
    if type(actual) is not type(expected) or actual!=expected:raise ValueError('fixture binding mismatch: '+key)
def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600)
    with os.fdopen(fd,'wb') as out:out.write(data);out.flush();os.fsync(out.fileno())
def prepare(fixture_dir,image_file,output_dir,deadline=120000,max_tokens=256,valid_ms=600000):
    if type(deadline) is not int or not 1000<=deadline<=600000 or type(max_tokens) is not int or not 1<=max_tokens<=512 or type(valid_ms) is not int or not 1<=valid_ms<=600000:raise ValueError('request budget outside fixed contract')
    source=read(Path(__file__).parent.parent/'assets/official-gui-prompts.json',65536)
    if sha(source)!=SOURCE_SHA:raise ValueError('official GUI source pin mismatch')
    s=obj(source);prefix=s['builtin_prefix'];variable=s['builtin_variable']
    if sha(prefix.encode())!=PREFIX_SHA or sha(variable.encode())!=VARIABLE_SHA:raise ValueError('official template component pin mismatch')
    fixture=read(fixture_dir/'fixture.json',131072);f=obj(fixture);prompt=read(fixture_dir/'prompt.txt',65536);image=read(image_file,32*1024*1024)
    equal(f,'schema','hepta.mobimind.private-gui-fixture.v1')
    for key in ('source_repository','source_commit','source_path','source_git_blob'):equal(f,key,s[key])
    equal(f,'prefix_sha256',PREFIX_SHA);equal(f,'variable_sha256',VARIABLE_SHA)
    for key,expected in (('template_wrapping',False),('actions_executed',False),('one_shot_concatenation',True)):equal(f,key,expected)
    source_text(f['task_utf8'],32768);source_text(f['history_utf8'],16384)
    for name in ('task','history'):equal(f,name+'_sha256',sha(f[name+'_utf8'].encode()))
    rendered=(prefix.replace('{task}',f['task_utf8'])+variable.replace('{history}',f['history_utf8']).replace('<image_placeholder>','<img>screen</img>')).encode()
    if prompt!=rendered:raise ValueError('fixture prompt differs from exact official one-shot rendering')
    equal(f,'prompt_sha256',sha(prompt));equal(f,'prompt_bytes',len(prompt));equal(f,'image_sha256',sha(image));equal(f,'image_bytes',len(image))
    if len(image)<33 or image[:8]!=b'\x89PNG\r\n\x1a\n' or image[12:16]!=b'IHDR':raise ValueError('original PNG required')
    width,height=struct.unpack('>II',image[16:24])
    if not (32<=width<=8192 and 32<=height<=8192 and width*height<=32000000):raise ValueError('image geometry outside bound')
    equal(f,'image_width',width);equal(f,'image_height',height)
    output_dir=output_dir.resolve();output_dir.mkdir(mode=0o700)
    request_id=uuid.uuid4().hex;nonce=secrets.token_hex(32);now=time.time_ns()//1000000
    request={'schema':'hepta.private-mobimind-probe.v1','nonce':nonce,'request_id':request_id,'fixture_sha256':sha(fixture),'created_wall_ms':now,'expires_wall_ms':now+valid_ms,'deadline_ms':deadline,'max_tokens':max_tokens}
    relative='files/mobi-probe-inputs/'+request_id+'/';members={relative+'fixture.json':fixture,relative+'prompt.txt':prompt,relative+'image.png':image,
        'files/mobi-prompt-source.json':source,'files/mobi-probe-request.json':(json.dumps(request,ensure_ascii=False,indent=2)+'\n').encode()}
    for name,data in members.items():write(output_dir/name,data)
    handoff={'schema':'hepta.mobimind.private-app-request-handoff.v1','request_id':request_id,'nonce_sha256':sha(nonce.encode()),'fixture_sha256':sha(fixture),
        'owner_sha256':f['task_sha256'],'image_sha256':sha(image),'prompt_sha256':sha(prompt),'deadline_ms':deadline,'max_tokens':max_tokens,'expires_wall_ms':now+valid_ms,
        'nonce_source':'files/mobi-probe-request.json','intent_boolean_extra':'auto_mobi_probe','intent_nonce_extra':'mobi_nonce','private_owner_mode':'0600','private_directory_mode':'0700',
        'actions_executed':False,'phone_contacted':False,'model_assets_included':False,'model_directory':'files/model/mobimind-1.5-2b-w8a8-0717-f02848b6',
        'files':[{'path':name,'bytes':len(data),'sha256':sha(data)} for name,data in members.items()]}
    write(output_dir/'REQUEST-HANDOFF.json',(json.dumps(handoff,ensure_ascii=False,indent=2)+'\n').encode())
    return handoff
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--fixture-dir',type=Path,required=True);p.add_argument('--image-file',type=Path,required=True);p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--deadline-ms',type=int,default=120000);p.add_argument('--max-tokens',type=int,default=256);p.add_argument('--valid-ms',type=int,default=600000);a=p.parse_args()
    value=prepare(a.fixture_dir,a.image_file,a.output_dir,a.deadline_ms,a.max_tokens,a.valid_ms)
    print(json.dumps({k:value[k] for k in ('request_id','nonce_sha256','fixture_sha256','expires_wall_ms','phone_contacted','actions_executed')}))
if __name__=='__main__':main()
