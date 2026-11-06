"""Read-only accounting of the already failed source-publication job."""
import base64
import hashlib
import json
import os
from pathlib import Path
import stat
import zlib

B=Path('/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1')
BINDING=B/'followthrough-fc33-negative-source-binding-r5-01'
DERIVED=B/'fc33-negative-sources-native-v3-r5-01'
TRANSPORT=B/'followthrough-fc33-negative-source-transport-r5-01'
META=('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns')
BOOK={}

def need(value, why):
    if not value:raise ValueError(why)

def sha(raw):return hashlib.sha256(raw).hexdigest()
def pin(raw):return {'bytes':len(raw),'sha256':sha(raw)}
def metadata(value):return [getattr(value,k)for k in META]
def enc(value):return (json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2,allow_nan=False)+'\n').encode()

def strict(raw):
    def pairs(rows):
        value={}
        for key,item in rows:need(key not in value,'duplicate JSON');value[key]=item
        return value
    return json.loads(raw,object_pairs_hook=pairs,parse_constant=lambda _:need(False,'nonfinite JSON'))

def read(path, expected=None):
    path=Path(path);need(path.is_absolute()and path.resolve(strict=True)==path,'canonical original')
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC)
    try:
        first=os.fstat(fd);need(stat.S_ISREG(first.st_mode)and first.st_nlink==1 and 0<=first.st_size<=16*1024*1024,'bounded regular original')
        with os.fdopen(fd,'rb',closefd=False)as stream:raw=stream.read(first.st_size+1)
        need(len(raw)==first.st_size and metadata(first)==metadata(os.fstat(fd))==metadata(path.lstat()),'whole byte/full9 bookend')
        if expected is not None:need(pin(raw)==expected,'selected original byte pin')
        row={'path':str(path),**pin(raw),'metadata':metadata(first)}
        need(str(path)not in BOOK or BOOK[str(path)]==row,'same original generation')
        BOOK[str(path)]=row;return raw
    finally:os.close(fd)

def listing(root):
    need(root.resolve(strict=True)==root,'canonical source output root')
    result=[];directories=[]
    for current,names,files in os.walk(root,followlinks=False):
        path=Path(current);info=path.lstat();need(stat.S_ISDIR(info.st_mode)and stat.S_IMODE(info.st_mode)==0o700,'private complete source directory')
        need(all(not(path/name).is_symlink()for name in names),'no source directory aliases')
        directories.append({'path':str(path),'metadata':metadata(info),'names':sorted(names+files)})
        result.extend(str((path/name).relative_to(root))for name in files)
        need(len(result)<=256 and len(directories)<=128,'bounded published source tree')
    return sorted(result),directories

def main():
    compressed=read(TRANSPORT/'SOURCE-PAYLOAD.zlib',{'bytes':711272,'sha256':'324bf65adb34b22e870ab8d791216ffcc50f360685934ab7696694b866b5a873'})
    decoder=zlib.decompressobj();raw=decoder.decompress(compressed,2521096)
    need(decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail and
         pin(raw)=={'bytes':2521095,'sha256':'0d178167de8e3e983b64bc116d8a87d4d04b305d58668a69da5eec670570cf7e'},'whole original prepared payload')
    payload=strict(raw);need(len(payload['files'])==177 and payload['binding_root']==str(BINDING),'same prepared177 input set')
    names,directories=listing(BINDING)
    expected={row['path']:row for row in payload['files']}
    extra={'PUBLISHER-SOURCE.executed.py','SOURCE-READER-DERIVATION.json','PUBLISHER-DERIVATION.json','DERIVATION.json'}
    need(set(names)==set(expected)|extra and len(names)==181,'exact181 input publication members')
    bodies={}
    for name in names:
        row=expected.get(name);body=read(BINDING/name,None if row is None else{k:row[k]for k in('bytes','sha256')})
        bodies[name]=body
        if row is not None:
            value=payload['blobs'][row['sha256']]
            original=value['content'].encode()if value['encoding']=='utf-8'else base64.b64decode(value['content'],validate=True)
            need(body==original,'published input differs from complete retained prepared bytes')
    need(pin(bodies['PUBLISHER-SOURCE.executed.py'])=={'bytes':19652,'sha256':'581efadeed85af47e98c68c4037cee4b2599d00987df1f78ca753e917e729335'},'exact actually executed publisher')
    derivation=strict(bodies['DERIVATION.json'])
    need(derivation['state']=='COMPLETE_SOURCE_INPUT_COPIES_ONLY_NO_ACTUAL_TASK'and
         derivation['reference_sources']==171 and derivation['whole_constructor_inverse']is True,'input publication only, not derived completion')
    need(len(derivation['files'])==180 and {r['path']for r in derivation['files']}=={str(BINDING/n)for n in names if n!='DERIVATION.json'},'complete input terminal member inventory')
    for row in derivation['files']:need(pin(bodies[str(Path(row['path']).relative_to(BINDING))])=={k:row[k]for k in('bytes','sha256')},'terminal source member byte pin')
    source_inputs=strict(bodies['SOURCE-INPUTS.json'])
    policy=read(source_inputs['actual_policy']['path'],{k:source_inputs['actual_policy'][k]for k in('bytes','sha256')})
    adoption_raw=read(source_inputs['policy_adoption']['path'],{k:source_inputs['policy_adoption'][k]for k in('bytes','sha256')})
    adoption=strict(adoption_raw)
    need(adoption['actual_export']==source_inputs['actual_policy'],'actual export exact3 path/bytes/hash relationship')
    first=B.stat()
    try:DERIVED.lstat()
    except OSError as error:need(error.errno==2,'unknown derived namespace absence');derived='ENOENT'
    else:derived='PRESENT_RECONCILE_ONLY'
    need(metadata(first)==metadata(B.stat()),'derived absence parent bookend')
    need(listing(BINDING)==(names,directories),'whole input directory/full9/membership bookend')
    for row in list(BOOK.values()):read(row['path'],{k:row[k]for k in('bytes','sha256')})
    print(json.dumps({'schema':'hepta.fc33.failed-negative-source-publication-inspection.v1',
        'failed_job_id':'1a1b2488d00-fc05-7d52','failed_operation_replayed':False,
        'binding':{'path':str(BINDING),'files':len(names),'directory_count':len(directories),
            'all177_prepared_members_equal':True,'all180_terminal_members_verified':True,
            'derivation':BOOK[str(BINDING/'DERIVATION.json')],
            'member_byte_total':sum(len(x)for x in bodies.values()),'member_book_sha256':sha(enc([BOOK[str(BINDING/n)]for n in names]))},
        'derived':{'path':str(DERIVED),'state':derived,'parent_metadata':metadata(first)},
        'adoption':{'actual_export_exact3_equals_selected_input':True,'actual_export':adoption['actual_export'],
            'schema':adoption['schema'],'release_id':adoption['release_id'],
            'root_decision_schema':adoption['root_decision']['schema'],
            'top_level_delta_atom_count':len(adoption['root_decision']['permission_atoms'])},
        'complete_original_count':len(BOOK),'complete_unique_path_bytes':sum(r['bytes']for r in BOOK.values()),
        'phone_calls':0,'model_requests':0,'native_dispatches':0,'source_publication_performed':False,
        'source_constructor_positive_run':False,'actual_BUILD':None,'actual_READY':None},sort_keys=True))

if __name__=='__main__':main()
