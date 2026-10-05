#!/usr/bin/env python3
"""Private owner graph collector/gate. P0 schemas and release authority are separate.

Git observations are sequential, not an atomic snapshot. A checkout collector
reads every tracked object and retains raw commit/tree/status evidence. The
graph gate requires all 1170 inventories, before/after vectors, the exact 38 private
projects, manifest-repository evidence, two non-Git Motorola trees and a
measured empty generated-source delta. Generated source is held until a
separate generator/input/content contract is implemented; elapsed time or
an ignored status does not authorize it. This tool never updates a checkout.
"""
from __future__ import annotations
import argparse, base64, datetime, hashlib, importlib.util, io, json, math, os
from pathlib import Path, PurePosixPath
import posixpath, re, stat, sys, tarfile, time, xml.etree.ElementTree as ET

PROFILE = 'owner-open-whole-control-v4'
INPUT_SCHEMA = 'org.trillionnium.owner-source-provenance-input.v4'
BOM_SCHEMA = 'org.trillionnium.owner-source-bom.v4'
INVENTORY_SCHEMA = 'org.trillionnium.owner-git-content-inventory.v3'
VECTOR_SCHEMA = 'org.trillionnium.owner-source-observation-vector.v1'
MANIFEST_COUNT, PRIVATE_COUNT = 1170, 38
ORIGINAL_COUNT = MANIFEST_COUNT - PRIVATE_COUNT - 1
PRIVATE_PROJECT_PATHS=frozenset({'packages/apps/Settings', 'packages/providers/TelephonyProvider', 'external/exfatprogs', 'device/trillionnium/sepolicy', 'packages/modules/adb', 'hardware/interfaces', 'device/motorola/fogos', 'packages/modules/Bluetooth', 'packages/providers/MediaProvider', 'packages/modules/Uwb', 'packages/apps/Seedvault', 'system/core', 'frameworks/base', 'external/libcupsfilters', 'packages/apps/TV', 'build/make', 'vendor/trillionnium', 'external/freetype', 'external/libhevc', 'hardware/nxp/secure_element', 'frameworks/layoutlib', 'packages/apps/TrillionniumAiShell', 'trillionnium-sdk', 'external/aws-sdk-java-v2', 'packages/modules/Wifi', 'bionic', 'external/libpng', 'packages/apps/TrillionniumAiAuthority', 'device/motorola/sm6375-common', 'packages/modules/Nfc', 'art', 'external/libppd', 'kernel/motorola/sm6375', 'packages/services/Telephony', 'external/wpa_supplicant_8', 'system/extras', 'external/libopenapv', 'frameworks/av'})
ASB_CATALOG_HELPER_SHA='fea8c1d1fb459f5f124fb11d563cc6282cee0bc9b49608c0412b8b3c904036c4'
ASB_CATALOG_SHA = 'c4436eb8f68adc50235e4b549e74a4337d17b4ce8f99b216e3aa189030263f3c'
MAX_GRAPH_FILES=5_000_000
MAX_GRAPH_METADATA=2*1024*1024*1024
MAX_RETAINED_METADATA=128*1024*1024
MAX_RETAINED_FILES=500_000
MAX_GITLINKS=1024
MAX_GITLINK_DEPTH=40
MOTOROLA_PATHS = {'vendor/motorola/fogos', 'vendor/motorola/sm6375-common'}
BOUNDED_HELPER_SHA = '9f9b40baa7855a92bac2e29ca612704ff85516a41b310e2a481c5c3a29923cf5'
# Pack windows/cache stay finite within the separate process address-space
# ceiling. These Git settings are not a hard RSS or whole-process quota.
GIT_PACK_OPTIONS = ('-c', 'core.packedGitWindowSize=32m',
                    '-c', 'core.packedGitLimit=128m')
HEX40, HEX64 = re.compile('[0-9a-f]{40}'), re.compile('[0-9a-f]{64}')
LEGACY_ROLES = {'ai_shell', 'ai_authority', 'capability_lease', 'p01_runtime', 'legacy_shell_broker'}
SOURCE_CHECKER='tools/verify-owner-open-android-source-closure.py'
SOURCE_CHECKER_SHA='82fb466f6a11116c45d147c8f0b41060aefe9cbe6020defeb3c12b83761a341f'
SDK_CHECKER='tools/verify-owner-open-sdk-selection.py'
SDK_CHECKER_SHA='159eaff813ab1ffdb34e50477d0b339bd7b0d12a1a92fee8f40ac30939fabf7e'
MANIFEST_PROJECTIONS=json.loads('[{"project":"build/make","kind":"linkfile","source":"CleanSpec.mk","destination":"build/CleanSpec.mk"},{"project":"build/make","kind":"linkfile","source":"buildspec.mk.default","destination":"build/buildspec.mk.default"},{"project":"build/make","kind":"linkfile","source":"core","destination":"build/core"},{"project":"build/make","kind":"linkfile","source":"envsetup.sh","destination":"build/envsetup.sh"},{"project":"build/make","kind":"linkfile","source":"target","destination":"build/target"},{"project":"build/make","kind":"linkfile","source":"tools","destination":"build/tools"},{"project":"external/chromium-webview/patches","kind":"linkfile","source":"os_pickup.bp","destination":"external/chromium-webview/Android.bp"},{"project":"external/chromium-webview/patches","kind":"linkfile","source":"README","destination":"external/chromium-webview/README"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_aosp.mk","destination":"hardware/qcom/Android.mk"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_sepolicy_vndr.mk","destination":"device/qcom/sepolicy_vndr/SEPolicy.mk"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/msm8953/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup.bp","destination":"hardware/qcom-caf/msm8998/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sdm660/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sdm845/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8150/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8250/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8350/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8450/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8450-6.6/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8550/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8650/Android.bp"},{"project":"hardware/qcom-caf/common","kind":"linkfile","source":"os_pickup_qssi.bp","destination":"hardware/qcom-caf/sm8750/Android.bp"},{"project":"trusty/host/common","kind":"linkfile","source":"bazel/WORKSPACE.bazel","destination":"trusty/WORKSPACE.bazel"},{"project":"trusty/host/common","kind":"linkfile","source":"bazel/bazelrc","destination":"trusty/.bazelrc"},{"project":"trusty/vendor/google/aosp","kind":"copyfile","source":"lk_inc.mk","destination":"lk_inc.mk"}]')

class SourceError(ValueError): pass
def require(condition, message):
    if not condition: raise SourceError(message)
def validate_private_paths(value):
    require(type(value) in (list, set, frozenset) and len(value)==PRIVATE_COUNT,
            'v4 exact38 private project count required')
    require(all(type(path) is str for path in value) and
            len(set(value))==PRIVATE_COUNT and set(value)==PRIVATE_PROJECT_PATHS,
            'v4 exact38 private project namespace required')
    return set(value)
def git_query_failure(label, project, root, args, result):
    # Only bounded public Git diagnostics. Each escaped byte expands to at
    # most four ASCII characters, so the retained excerpt is at most 2 KiB.
    stderr=result.stderr
    excerpt=repr(stderr[:512])[2:-1]
    flags={key:getattr(result,key,False) for key in
           ('timed_out','output_limit_exceeded','spawn_error','capture_error','cleanup_error')}
    return (label+': project='+repr(project)+' root='+repr(str(root))+
            ' argv='+repr(args)+' actual_rc='+repr(result.returncode)+
            ' stderr_bytes='+str(len(stderr))+' stderr_sha256='+sha(stderr)+
            ' stderr_escaped='+excerpt+' stderr_excerpt_truncated='+str(len(stderr)>512)+
            ' process_flags='+repr(flags))
def check(deadline):
    if time.monotonic() >= deadline: raise TimeoutError('owner source observer absolute deadline')
def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False, allow_nan=False)+'\n').encode()
def sha(raw): return hashlib.sha256(raw).hexdigest()
def git_oid(kind, raw): return hashlib.sha1(kind.encode()+b' '+str(len(raw)).encode()+b'\0'+raw).hexdigest()
def hexvalue(value, pattern, label):
    require(type(value) is str and pattern.fullmatch(value) is not None, label+' digest syntax')
    return value
def relative(value):
    require(type(value) is str and bool(value) and len(value.encode()) <= 4096, 'relative source path bound')
    p = PurePosixPath(value)
    require(not value.startswith('/') and '\\' not in value and str(p)==value and
            all(part not in ('', '.', '..', '.git') for part in p.parts) and
            not any(ord(c)<32 or ord(c)==127 for c in value), 'noncanonical source path')
    return value
def exact(value, keys, label):
    require(type(value) is dict and set(value)==set(keys), label+' exact fields required')
def parse(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result, 'duplicate JSON key');result[key]=value
        return result
    try:
        return json.loads(raw.decode(), object_pairs_hook=pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(SourceError('nonfinite JSON')))
    except (UnicodeError, RecursionError, json.JSONDecodeError) as e:
        raise SourceError('invalid bounded JSON') from e
def identity(s):
    return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def read_stable(path, maximum, deadline):
    p=Path(path)
    require(p.is_absolute() and p.resolve(strict=True)==p, 'canonical absolute input required')
    before=p.lstat()
    require(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=maximum, 'ordinary input byte bound')
    # FileIO owns close semantics. Never retry a released raw numeric FD.
    with io.FileIO(os.open(p,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb',closefd=True) as f:
        require(identity(os.fstat(f.fileno()))==identity(before), 'input entry changed before read')
        raw=bytearray()
        while True:
            check(deadline);piece=f.read(min(1024*1024,maximum+1-len(raw)))
            if not piece:break
            raw.extend(piece);require(len(raw)<=maximum,'actual input byte bound')
        require(identity(os.fstat(f.fileno()))==identity(before) and identity(p.lstat())==identity(before),'input changed during read')
    result=bytes(raw);check(deadline);return result
def descriptor(path, raw): return dict(path=str(path),bytes=len(raw),sha256=sha(raw))
def read_descriptor(value, deadline, maximum=128*1024*1024):
    exact(value, ('path','bytes','sha256'), 'input descriptor')
    require(type(value['bytes']) is int and 0<=value['bytes']<=maximum,'descriptor byte bound')
    hexvalue(value['sha256'],HEX64,'input');raw=read_stable(value['path'],maximum,deadline)
    require(len(raw)==value['bytes'] and sha(raw)==value['sha256'],'input descriptor custody moved')
    return raw
def measure_regular(path,maximum,deadline):
    """Hash actual bytes without allocating the whole potentially large file."""
    path=Path(path);require(path.is_absolute() and path.resolve(strict=True)==path,'canonical tracked source required')
    before=path.lstat();require(stat.S_ISREG(before.st_mode) and 0<=before.st_size<=maximum,'tracked ordinary byte bound')
    h=hashlib.sha256();g=hashlib.sha1(b'blob '+str(before.st_size).encode()+b'\0');total=0
    with io.FileIO(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb',closefd=True) as f:
        require(identity(os.fstat(f.fileno()))==identity(before),'tracked entry changed before read')
        while True:
            check(deadline);block=f.read(1024*1024)
            if not block:break
            total+=len(block);require(total<=maximum,'actual tracked byte bound');h.update(block);g.update(block)
        require(total==before.st_size and identity(os.fstat(f.fileno()))==identity(before) and identity(path.lstat())==identity(before),'tracked identity changed while hashing')
    result=dict(bytes=total,sha256=h.hexdigest(),git_blob=g.hexdigest(),git_mode='100755' if before.st_mode&0o111 else '100644',mode=stat.S_IMODE(before.st_mode));check(deadline);return result
def decode64(value, maximum, label):
    require(type(value) is str and len(value)<=4*((maximum+2)//3), label+' base64 byte bound')
    try: raw=base64.b64decode(value, validate=True)
    except ValueError as e: raise SourceError(label+' invalid base64') from e
    require(len(raw)<=maximum, label+' actual byte bound');return raw

def tree_oid(rows):
    """Reconstruct full Git tree objects, including Git's directory sort rule."""
    root={}
    for row in rows:
        path=relative(row['path']);parts=path.split('/');node=root
        require(row['git_mode'] in ('100644','100755','120000','160000'),'unsupported Git mode')
        oid=hexvalue(row['git_commit'] if row['git_mode']=='160000' else row['git_blob'],HEX40,'tracked object')
        for component in parts[:-1]:
            if component not in node:node[component]={}
            require(type(node[component]) is dict,'source file/directory collision');node=node[component]
        require(parts[-1] not in node,'duplicate source path');node[parts[-1]]=(row['git_mode'],oid)
    def build(node):
        entries=[]
        for name,item in node.items():
            mode,oid=('40000',build(item)) if type(item) is dict else item
            entries.append((name.encode()+ (b'/' if mode=='40000' else b''),mode,name.encode(),oid))
        body=b''.join(mode.encode()+b' '+name+b'\0'+bytes.fromhex(oid) for _,mode,name,oid in sorted(entries))
        return git_oid('tree',body)
    return build(root)

def parse_ls_tree(raw):
    require(not raw or raw.endswith(b'\0'),'truncated raw Git ls-tree')
    rows=[]
    for field in raw.split(b'\0')[:-1]:
        try: header,path=field.split(b'\t',1);mode,kind,oid=header.decode().split(' ');path=path.decode()
        except (ValueError,UnicodeError) as e:raise SourceError('invalid raw Git ls-tree') from e
        require((kind=='blob' and mode in ('100644','100755','120000')) or
                (kind=='commit' and mode=='160000'),'unsupported tracked Git object')
        row=dict(path=relative(path),git_mode=mode)
        row['git_commit' if mode=='160000' else 'git_blob']=hexvalue(oid,HEX40,'raw tracked object')
        rows.append(row)
    require(len(rows)<=250000 and len({r['path'] for r in rows})==len(rows),'tracked count/duplicate bound')
    return rows

def observe_unmaterialized_gitlink(root,path,deadline):
    """Observe an absent or empty gitlink, without opening submodule contents.

    A commit reference is not a measured commit body or a source payload.
    Materialized submodules require a separate recursive content contract.
    """
    root=Path(root);parts=relative(path).split('/')
    require(len(parts)<=MAX_GITLINK_DEPTH,'gitlink path depth bound')
    require(root.is_absolute() and root.resolve(strict=True)==root,'canonical gitlink checkout required')
    opened=[];parents=[];entry=None;absent=None
    try:
        old=root.lstat();fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        opened.append((root,fd,identity(old)))
        require(identity(os.fstat(fd))==identity(old),'gitlink root FD differs')
        for number,part in enumerate(parts):
            check(deadline);parent=opened[-1][1]
            if number==0:parents.append(dict(path='',identity=list(opened[-1][2])))
            name='/'.join(parts[:number+1])
            try:s=os.stat(part,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:
                absent=name;break
            require(stat.S_ISDIR(s.st_mode),'gitlink replaced by symlink or special entry: '+path)
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
            opened.append((root/name,child,identity(s)))
            require(identity(os.fstat(child))==identity(s),'gitlink directory FD differs')
            if number==len(parts)-1:
                entry=list(identity(s))
                with os.scandir(child) as scan:
                    check(deadline)
                    require(next(scan,None) is None,'materialized gitlink requires recursive content contract: '+path)
                break
            parents.append(dict(path=name,identity=list(identity(s))))
        if absent is not None:
            try:os.stat(parts[len(parents)-1],dir_fd=opened[-1][1],follow_symlinks=False)
            except FileNotFoundError:pass
            else:raise SourceError('missing gitlink entry appeared during observation')
        for directory,fd,old in opened:
            check(deadline);require(identity(os.fstat(fd))==old and identity(directory.lstat())==old,'gitlink parent or entry changed')
        return dict(state='missing' if absent is not None else 'empty',absent_path=absent,parent_entries=parents,entry_identity=entry,entries=[])
    finally:
        for _,fd,_ in reversed(opened):os.close(fd)

def validate_gitlinks(rows,expected):
    require(type(rows) is list and len(rows)<=MAX_GITLINKS and len(canonical(rows))<=2*1024*1024,'bounded explicit gitlink references required')
    refs={}
    for row in rows:
        exact(row,('path','git_mode','git_commit','worktree_before','worktree_after','submodule_content_measured'),'gitlink reference')
        path=relative(row['path']);parts=path.split('/');require(len(parts)<=MAX_GITLINK_DEPTH and path not in refs,'duplicate/deep gitlink reference')
        require(row['git_mode']=='160000' and row['submodule_content_measured'] is False,'commit reference is not a measured blob/submodule')
        hexvalue(row['git_commit'],HEX40,'gitlink commit')
        require(row['worktree_before']==row['worktree_after'],'gitlink worktree state changed')
        value=row['worktree_before'];exact(value,('state','absent_path','parent_entries','entry_identity','entries'),'gitlink worktree state')
        require(value['state'] in ('missing','empty') and value['entries']==[],'unmeasured materialized gitlink held')
        parents=value['parent_entries'];require(type(parents) is list and 1<=len(parents)<=len(parts),'gitlink physical parent closure required')
        for number,parent in enumerate(parents):
            exact(parent,('path','identity'),'gitlink parent');require(parent['path']=='/'.join(parts[:number]),'gitlink parent namespace differs')
            ident=parent['identity'];require(type(ident) is list and len(ident)==9 and all(type(n) is int for n in ident) and stat.S_ISDIR(ident[2]),'gitlink held-parent identity unavailable')
        if value['state']=='missing':
            require(value['entry_identity'] is None and value['absent_path']=='/'.join(parts[:len(parents)]),'gitlink absence boundary differs')
        else:
            ident=value['entry_identity'];require(value['absent_path'] is None and len(parents)==len(parts) and type(ident) is list and len(ident)==9 and all(type(n) is int for n in ident) and stat.S_ISDIR(ident[2]),'gitlink empty-directory identity unavailable')
        refs[path]=row
    require(set(refs)=={r['path'] for r in expected},'whole tracked gitlink reference set differs')
    for ref in expected:require(all(refs[ref['path']][k]==v for k,v in ref.items()),'gitlink commit/mode differs from raw tree')
    return rows
def parse_lfs_pointer(raw):
    require(type(raw) is bytes and len(raw)<=1024,'bounded canonical LFS pointer required')
    match=re.fullmatch(rb'version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize (0|[1-9][0-9]*)\n',raw)
    require(match is not None,'unsupported/noncanonical LFS pointer')
    size=int(match[2]);require(size<=2*1024**3,'LFS payload byte boundary');return match[1].decode(),size
def validate_status(raw,lfs_paths,missing_gitlinks=()):
    require(not raw or raw.endswith(b'\0'),'raw Git status truncated')
    seen=set()
    for item in raw.split(b'\0')[:-1]:
        require(len(item)>3 and item[:3] in (b' M ',b' D '),'dirty/staged/untracked/ignored source held')
        try:path=relative(item[3:].decode())
        except UnicodeError as e:raise SourceError('status path encoding') from e
        allowed=lfs_paths if item[:3]==b' M ' else missing_gitlinks
        require(path in allowed and path not in seen,'ordinary dirty source or duplicate status held');seen.add(path)
    return seen

def validate_inventory(value):
    require(type(value) is dict and value.get('schema')==INVENTORY_SCHEMA and value.get('complete') is True,'complete owner Git content inventory required')
    head=hexvalue(value.get('head'),HEX40,'head');tree=hexvalue(value.get('tree'),HEX40,'tree')
    commit=decode64(value.get('raw_commit_base64'),1024*1024,'commit')
    require(git_oid('commit',commit)==head and commit.startswith(('tree '+tree+'\n').encode()),'raw commit/head/tree mismatch')
    raw=decode64(value.get('raw_ls_tree_base64'),32*1024*1024,'ls-tree');all_expected=parse_ls_tree(raw)
    gitlinks=validate_gitlinks(value.get('gitlinks'),[r for r in all_expected if r['git_mode']=='160000'])
    expected=[r for r in all_expected if r['git_mode']!='160000']
    rows=value.get('source_files');require(type(rows) is list and len(rows)==len(expected),'whole tracked content inventory missing')
    observed={}
    for row in rows:
        exact(row,('path','git_mode','git_blob','bytes','sha256','symlink_target','lfs'),'tracked content row')
        require(row['git_mode'] in ('100644','100755','120000'),'tracked payload must be a blob, not a gitlink')
        path=relative(row['path']);require(path not in observed,'duplicate measured source path')
        require(type(row['bytes']) is int and 0<=row['bytes']<=2*1024**3,'tracked file byte bound')
        hexvalue(row['sha256'],HEX64,'content');observed[path]=row
        require((row['git_mode']=='120000')==(type(row['symlink_target']) is str),'tracked symlink shape')
        if row['git_mode']=='120000':
            target=row['symlink_target'].encode();require(len(target)==row['bytes'] and sha(target)==row['sha256'] and git_oid('blob',target)==row['git_blob'],'symlink target/blob mismatch')
        if row['lfs'] is not None:
            proof=row['lfs'];exact(proof,('pointer_base64','pointer_sha256','payload_oid_sha256','payload_bytes','attributes_raw_base64'),'LFS source proof');pointer=decode64(proof['pointer_base64'],1024,'LFS pointer');oid,size=parse_lfs_pointer(pointer)
            require(row['git_mode']!='120000' and git_oid('blob',pointer)==row['git_blob'] and sha(pointer)==proof['pointer_sha256'] and oid==proof['payload_oid_sha256']==row['sha256'] and type(proof['payload_bytes']) is int and size==proof['payload_bytes']==row['bytes'],'LFS original pointer/payload FD closure differs')
            attributes=decode64(proof['attributes_raw_base64'],8192,'committed LFS attributes');require(attributes==(path+'\0filter\0lfs\0').encode(),'LFS committed filter selection proof differs')
    require({r['path'] for r in expected}==set(observed),'tracked path set differs')
    for row in expected:
        actual=observed[row['path']];require(all(actual[k]==row[k] for k in row),'tracked blob/mode mismatch')
    require(tree_oid(rows+gitlinks)==tree,'whole tracked Git tree mismatch')
    require(value.get('status_query')==['status','--porcelain=v1','-z','--untracked-files=all','--ignored=matching'],'full raw status query required')
    lfs={p for p,r in observed.items() if r['lfs'] is not None}
    before=decode64(value.get('raw_status_before_base64'),8*1024*1024,'status');after=decode64(value.get('raw_status_after_base64'),8*1024*1024,'status')
    missing={r['path'] for r in gitlinks if r['worktree_before']['state']=='missing'}
    validate_status(before,lfs,missing);validate_status(after,lfs,missing);require(before==after,'raw source status changed during observation')
    require(value.get('external_git_filters_disabled') is True and value.get('index_matches_committed_tree') is True and value.get('uncommitted_attributes_empty') is True,'committed-only attribute/filter boundary unavailable')
    require(value.get('head_after')==head and value.get('tree_after')==tree,'checkout generation changed')
    require(type(value.get('source_bytes')) is int and value['source_bytes']==sum(r['bytes'] for r in rows),'measured source aggregate differs')
    return value

def bounded_module(deadline):
    path=Path(__file__).with_name('owner_bom_bounded_process.py').resolve()
    raw=read_stable(path,256*1024,deadline);require(sha(raw)==BOUNDED_HELPER_SHA,'pinned child observer changed')
    # SourceFileLoader can execute an unmeasured timestamp .pyc even when the
    # .py file has the expected digest. Compile the actual retained bytes.
    spec=importlib.util.spec_from_file_location('owner_bom_bound',path);m=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    require(sha(read_stable(path,256*1024,deadline))==BOUNDED_HELPER_SHA,'child observer moved on import');return m
def validate_git_query_seconds(seconds):
    require(type(seconds) in (int,float) and 1<=seconds<=300 and math.isfinite(seconds),'Git query deadline requires finite 1..300 seconds')
    return seconds

def collect_git_checkout(root, expected_head, expected_tree, deadline, project=None, git_query_seconds=30):
    validate_git_query_seconds(git_query_seconds)
    root=Path(root);require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(),'canonical checkout root required');project=relative(project) if project is not None else str(root)
    m=bounded_module(deadline)
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','GIT_ATTR_NOSYSTEM':'1','GIT_ALLOW_PROTOCOL':''}
    filter_options=[]
    def git(args, maximum=32*1024*1024, allowed=(0,)):
        check(deadline)
        try:
            r=m.run_bounded(['/usr/bin/git',*GIT_PACK_OPTIONS,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','maintenance.auto=false','-c','core.attributesFile=/dev/null','-c','credential.helper=',*filter_options,'-C',str(root),*args],timeout_seconds=min(git_query_seconds,deadline-time.monotonic()),maximum_output=maximum,env=env)
        except m.BoundedProcessError as error:
            raise SourceError(git_query_failure('actual Git capture failed',project,root,args,error)) from error
        require(r.returncode in allowed,git_query_failure('actual Git query failed',project,root,args,r));check(deadline);return r.stdout
    names=git(['config','--local','--name-only','--get-regexp',r'^filter\.'],1024*1024,(0,1)).decode().splitlines();filters={'lfs'}
    for name in names:
        match=re.fullmatch(r'filter\.([A-Za-z0-9_.-]{1,128})\.[A-Za-z0-9_.-]+',name);require(match is not None,'unsupported local Git filter key');filters.add(match[1])
    for name in sorted(filters):
        for kind,value in (('clean',''),('smudge',''),('process',''),('required','false')):filter_options+=['-c','filter.'+name+'.'+kind+'='+value]
    require(git(['rev-parse','--show-toplevel']).decode().rstrip('\n')==str(root),'checkout top-level differs')
    head=git(['rev-parse','HEAD']).decode().strip();tree=git(['rev-parse','HEAD^{tree}']).decode().strip()
    require((head,tree)==(expected_head,expected_tree),'actual checkout candidate differs')
    status_args=['status','--porcelain=v1','-z','--untracked-files=all','--ignored=matching']
    before=git(status_args,8*1024*1024)
    commit=git(['cat-file','commit',head],1024*1024);raw_tree=git(['ls-tree','-rz','--full-tree',head]);tracked=parse_ls_tree(raw_tree);rows=[r for r in tracked if r['git_mode']!='160000'];refs=[r for r in tracked if r['git_mode']=='160000'];total=0
    require(len(refs)<=MAX_GITLINKS,'gitlink reference count bound')
    gitlinks=[dict(r,worktree_before=observe_unmaterialized_gitlink(root,r['path'],deadline),submodule_content_measured=False) for r in refs]
    index_raw=git(['ls-files','--stage','-z','--full-name']);indexed=[]
    for field in index_raw.split(b'\0')[:-1]:
        header,path=field.split(b'\t',1);mode,oid,stage=header.decode().split(' ');require(stage=='0','unmerged/sparse source index held');row=dict(path=path.decode(),git_mode=mode);row['git_commit' if mode=='160000' else 'git_blob']=oid;indexed.append(row)
    require(sorted(indexed,key=lambda r:r['path'])==sorted(tracked,key=lambda r:r['path']),'index differs from committed raw tree')
    attribute_path=Path(git(['rev-parse','--git-path','info/attributes']).decode().strip());attribute_path=attribute_path if attribute_path.is_absolute() else root/attribute_path
    if attribute_path.exists() or attribute_path.is_symlink():require(read_stable(attribute_path,1024*1024,deadline)==b'','uncommitted Git attributes held')
    attributes={};has_attributes=any(PurePosixPath(r['path']).name=='.gitattributes' for r in rows)
    if has_attributes:
        batch=[];size=0
        def query_batch():
            raw=git(['check-attr','--cached','-z','filter','--',*batch],1024*1024);parts=raw.split(b'\0');require(parts[-1]==b'' and len(parts[:-1])==3*len(batch),'cached attribute output bound')
            for i in range(0,len(parts)-1,3):
                path,name,value=parts[i:i+3];require(name==b'filter' and path.decode() in batch,'cached attribute identity differs');attributes[path.decode()]=(value,path+b'\0filter\0'+value+b'\0')
        for row in rows:
            if batch and (len(batch)>=128 or size+len(row['path'].encode())>32768):query_batch();batch=[];size=0
            batch.append(row['path']);size+=len(row['path'].encode())+1
        if batch:query_batch()
    for row in rows:
        check(deadline);path=root/row['path'];target=None
        if row['git_mode']=='120000':
            old=path.lstat();require(stat.S_ISLNK(old.st_mode),'tracked symlink replaced');target=os.readlink(path);raw=target.encode()
            require(identity(path.lstat())==identity(old),'tracked symlink changed')
        else:
            measured=measure_regular(path,2*1024**3,deadline);require(measured['git_mode']==row['git_mode'],'tracked executable mode differs: '+row['path'])
        lfs=None
        if attributes.get(row['path'],(None,None))[0]==b'lfs':
            require(target is None,'LFS pointer symlink unsupported');pointer=git(['cat-file','blob',row['git_blob']],1024);oid,size=parse_lfs_pointer(pointer);require(measured['bytes']==size and measured['sha256']==oid,'unhydrated/mismatched LFS payload held');lfs=dict(pointer_base64=base64.b64encode(pointer).decode(),pointer_sha256=sha(pointer),payload_oid_sha256=oid,payload_bytes=size,attributes_raw_base64=base64.b64encode(attributes[row['path']][1]).decode())
        elif target is None:require(measured['git_blob']==row['git_blob'],'ordinary tracked content differs: '+row['path'])
        if target is not None:
            require(git_oid('blob',raw)==row['git_blob'],'tracked symlink content differs');measured=dict(bytes=len(raw),sha256=sha(raw))
        total+=measured['bytes'];require(total<=128*1024**3,'whole tracked byte bound');row.update(bytes=measured['bytes'],sha256=measured['sha256'],symlink_target=target,lfs=lfs)
    after=git(status_args,8*1024*1024);head_after=git(['rev-parse','HEAD']).decode().strip();tree_after=git(['rev-parse','HEAD^{tree}']).decode().strip()
    for row in gitlinks:row['worktree_after']=observe_unmaterialized_gitlink(root,row['path'],deadline)
    if attribute_path.exists() or attribute_path.is_symlink():require(read_stable(attribute_path,1024*1024,deadline)==b'','uncommitted Git attributes changed')
    result=dict(schema=INVENTORY_SCHEMA,root=str(root),head=head,tree=tree,raw_commit_base64=base64.b64encode(commit).decode(),raw_ls_tree_base64=base64.b64encode(raw_tree).decode(),status_query=status_args,raw_status_before_base64=base64.b64encode(before).decode(),raw_status_after_base64=base64.b64encode(after).decode(),head_after=head_after,tree_after=tree_after,source_files=rows,gitlinks=gitlinks,source_bytes=total,complete=True,external_git_filters_disabled=True,index_matches_committed_tree=True,uncommitted_attributes_empty=True,sequential_not_globally_atomic=True,external_global_immutability_proven=False,source_bom_qualified=False,independent_approval_asserted=False)
    validate_inventory(result);check(deadline);return result

def collect_blob_tree(root,label,deadline):
    """Two complete content passes on one non-Git tree; sequential, not atomic."""
    require(label in MOTOROLA_PATHS,'exact Motorola tree label required');root=Path(root)
    require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir() and not (root/'.git').exists(),'canonical non-Git blob-tree root required')
    def pass_():
        rows=[];total=0;pending=[root]
        while pending:
            check(deadline);directory=pending.pop();old=directory.lstat()
            require(stat.S_ISDIR(old.st_mode) and old.st_mode&0o400 and not old.st_mode&0o7022,'non-Git directory mode boundary')
            with os.scandir(directory) as scan:
                for entry in scan:
                    check(deadline);path=Path(entry.path);kind=path.lstat();name=relative(str(path.relative_to(root)))
                    require(len(rows)<250000,'non-Git full entry bound')
                    if stat.S_ISDIR(kind.st_mode):
                        pending.append(path);row=dict(path=name,kind='directory',bytes=0,sha256=sha(b''),mode=stat.S_IMODE(kind.st_mode))
                    else:
                        require(stat.S_ISREG(kind.st_mode),'unsupported non-Git symlink/special file held');m=measure_regular(path,2*1024**3,deadline);total+=m['bytes'];require(total<=16*1024**3,'non-Git aggregate byte bound');row=dict(path=name,kind='regular',bytes=m['bytes'],sha256=m['sha256'],mode=m['mode'])
                    require(row['mode']&0o400 and not row['mode']&0o7022,'non-Git entry mode boundary');rows.append(row)
            require(identity(directory.lstat())==identity(old),'non-Git directory changed during traversal')
        check(deadline);return sorted(rows,key=lambda r:r['path'])
    before=pass_();after=pass_();require(before==after,'non-Git before/after actual content differs')
    require(after,'empty Motorola source held');digest=sha(canonical(after));result=dict(schema='org.trillionnium.owner-non-git-content-tree.v1',path=label,root=str(root),entries=after,before_inventory_sha256=digest,after_inventory_sha256=digest,complete=True,observations_sequential_not_globally_atomic=True,external_global_immutability_proven=False,source_bom_qualified=False);check(deadline);return result

def verify_control_archive(raw, inventory, expected_sha, expected_count, deadline):
    require(inventory.get('gitlinks')==[],'control archive cannot reproduce unmaterialized gitlinks')
    validate_inventory(inventory);require(sha(raw)==expected_sha,'control archive bytes differ')
    expected={r['path']:r for r in inventory['source_files']};observed={};total=0;directories=set()
    with tarfile.open(fileobj=io.BytesIO(raw),mode='r:gz') as t:
        for member in t:
            check(deadline);path=relative(member.name)
            require(not member.pax_headers or set(member.pax_headers)<= {'mtime','atime','ctime','comment'},'unsupported archive extended identity')
            if member.isdir():
                require(path not in directories and path not in observed and any(p.startswith(path+'/') for p in expected),'duplicate/untracked archive directory');directories.add(path);continue
            require(member.isfile() and path not in observed and path not in directories,'archive nonregular/duplicate path')
            require(path in expected and 0<=member.size<=2*1024**3,'archive path/byte bound')
            total+=member.size;require(total<=128*1024**3,'archive aggregate byte bound')
            stream=t.extractfile(member)
            with stream:body=stream.read(member.size+1)
            row=expected[path];mode='100755' if member.mode&0o111 else '100644'
            require(len(body)==row['bytes'] and sha(body)==row['sha256'] and git_oid('blob',body)==row['git_blob'] and mode==row['git_mode'],'archive/control blob or executable mode differs')
            observed[path]=True
    require(set(observed)==set(expected) and len(observed)==expected_count,'archive/control full source path set differs')
    check(deadline);return dict(regular_files=len(observed),source_bytes=total,sha256=expected_sha,all_archive_bytes_match_measured_git_tree=True)

def parse_manifest(raw):
    require(len(raw)<=8*1024*1024 and b'<!DOCTYPE' not in raw.upper() and b'<!ENTITY' not in raw.upper(),'manifest XML bound/declaration')
    try:root=ET.fromstring(raw)
    except ET.ParseError as e:raise SourceError('invalid resolved manifest XML') from e
    require(root.tag=='manifest' and not root.findall('include') and not root.findall('remove-project') and not root.findall('extend-project'),'fully resolved manifest required')
    rows={}
    for node in root.findall('project'):
        path=relative(node.get('path',node.get('name')));name=node.get('name');revision=hexvalue(node.get('revision'),HEX40,'manifest revision')
        require(path not in rows and type(name) is str and name,'duplicate/unnamed resolved manifest project')
        rows[path]=dict(path=path,name=name,revision=revision)
    require(len(rows)==MANIFEST_COUNT and 'trillionnium-os' in rows,'exact owner1170 whole-control manifest required')
    return rows
def manifest_projections(raw):
    parse_manifest(raw);root=ET.fromstring(raw);rows=[];seen=set()
    for project in root.findall('project'):
        path=relative(project.get('path',project.get('name')))
        for node in project:
            if node.tag not in ('linkfile','copyfile'):
                require(node.tag=='annotation','unsupported manifest project source projection');continue
            require(set(node.attrib)=={'src','dest'} and not len(node),'projection exact src/dest attributes required')
            source=relative(node.get('src'));dest=relative(node.get('dest'));require(dest not in seen,'duplicate manifest projection destination');seen.add(dest);rows.append(dict(project=path,kind=node.tag,source=source,destination=dest))
    require(sorted(rows,key=lambda x:x['destination'])==sorted(MANIFEST_PROJECTIONS,key=lambda x:x['destination']),'owner exact25 manifest source projections missing/extra/different')
    return rows
def projected_source_rows(declaration,inventories):
    project,source=declaration['project'],declaration['source'];require(project in inventories,'projection source project not measured');inv=inventories[project];exact_rows=[r for r in inv['source_files'] if r['path']==source]
    require(not any(source==r['path'] or source.startswith(r['path']+'/') or r['path'].startswith(source+'/') for r in inv['gitlinks']),'gitlink cannot supply projection contents')
    directory=not exact_rows;selected=[r for r in inv['source_files'] if r['path'].startswith(source+'/')] if directory else exact_rows
    require(selected,'manifest projection source missing');require(not directory or declaration['kind']=='linkfile','copyfile cannot project an unmeasured directory')
    rows=[]
    for row in selected:
        local=row['path'][len(source)+1:] if directory else ''
        rows.append(dict(path=local,git_mode=row['git_mode'],bytes=row['bytes'],sha256=row['sha256'],symlink_target=row['symlink_target']))
    return directory,sorted(rows,key=lambda x:x['path'])
def map_projection_path(name,projections,inventories):
    """Resolve only measured repo copy/link projections, never an unknown alias."""
    seen=set()
    for _ in range(40):
        require(name not in seen,'cyclic manifest projection');seen.add(name);matches=[]
        for declaration in projections:
            dest=declaration['destination']
            if name==dest:matches.append(declaration)
            elif name.startswith(dest+'/'):
                directory,_=projected_source_rows(declaration,inventories)
                if directory:matches.append(declaration)
        if not matches:return name
        declaration=max(matches,key=lambda r:len(r['destination']));suffix=name[len(declaration['destination']):]
        name=declaration['project']+'/'+declaration['source']+suffix
    raise SourceError('manifest projection chain limit')
def validate_projections(value,candidate,manifest_raw,inventories):
    require(value.get('schema')=='org.trillionnium.owner-manifest-projection-observations.v1' and value.get('complete') is True,'complete actual25 manifest projection observations required');check_tuple(value,candidate)
    require(value.get('resolved_manifest_sha256')==sha(manifest_raw),'manifest projection input custody differs');declared=manifest_projections(manifest_raw);observed=value.get('projections');require(type(observed) is list and len(observed)==len(declared),'full projection observation set missing')
    view=value.get('physical_view_root');require(type(view) is str and Path(view).is_absolute(),'actual projection physical view unavailable')
    generations=value.get('project_git_observations');require(type(generations) is dict and set(generations)=={r['project'] for r in declared},'all projection project generations missing')
    for project,observation in generations.items():
        require(observation.get('physical_work_tree')==str(Path(view)/project),'projection project physical namespace differs')
        expected=(inventories[project]['head']+'\n'+inventories[project]['tree']+'\n').encode();require(decode64(observation.get('raw_before_base64'),128,'projection generation')==decode64(observation.get('raw_after_base64'),128,'projection generation')==expected,'projection actual Git generation differs from selected source')
    by={}
    for row in observed:
        destination=relative(row.get('destination'));require(destination not in by,'duplicate measured projection destination');by[destination]=row
    require(set(by)=={r['destination'] for r in declared},'projection destination namespace differs')
    for declaration in declared:
        row=by[declaration['destination']];require(all(row.get(k)==v for k,v in declaration.items()),'projection declaration/measurement differs');directory,expected=projected_source_rows(declaration,inventories)
        require(row.get('actual_target_files')==expected and row.get('target_file_inventory_complete') is True,'projection target actual content/closure missing or differs')
        digest=sha(canonical(expected));require(row.get('before_target_inventory_sha256')==row.get('after_target_inventory_sha256')==digest,'projection before/after complete target bytes differ')
        if declaration['kind']=='copyfile':require(row.get('observed_kind')=='regular' and row.get('symlink_target') is None and not directory,'copyfile destination is not a measured regular source copy')
        else:
            target=row.get('symlink_target');require(row.get('observed_kind')=='symlink' and type(target) is str and target and not target.startswith('/') and '\\' not in target,'linkfile destination link missing/unsafe')
            resolved=posixpath.normpath(posixpath.join(posixpath.dirname(declaration['destination']),target));require(resolved==declaration['project']+'/'+declaration['source'],'manifest link destination redirects away from tracked source')
    return value
def _projection_target_snapshot(root,deadline,directory):
    root=Path(root);require(root.resolve(strict=True)==root,'canonical actual projection source target required')
    def one(path,local):
        old=path.lstat()
        if stat.S_ISLNK(old.st_mode):
            target=os.readlink(path);raw=target.encode();require(identity(path.lstat())==identity(old),'projected tracked link changed');return dict(path=local,git_mode='120000',bytes=len(raw),sha256=sha(raw),symlink_target=target)
        measured=measure_regular(path,2*1024**3,deadline);return dict(path=local,git_mode=measured['git_mode'],bytes=measured['bytes'],sha256=measured['sha256'],symlink_target=None)
    if not directory:return [one(root,'')]
    rows=[];dirs=set();pending=[root]
    while pending:
        check(deadline);path=pending.pop();old=path.lstat();require(stat.S_ISDIR(old.st_mode),'projection target directory unavailable')
        with os.scandir(path) as entries:
            for entry in entries:
                check(deadline);child=Path(entry.path);local=relative(str(child.relative_to(root)));require(len(rows)+len(dirs)<=250000,'projection target full entry bound')
                if entry.is_dir(follow_symlinks=False):pending.append(child);dirs.add(local)
                else:rows.append(one(child,local))
        require(identity(path.lstat())==identity(old),'projection target directory changed during traversal')
    inferred=set()
    for row in rows:
        parent=posixpath.dirname(row['path'])
        while parent:inferred.add(parent);parent=posixpath.dirname(parent)
    require(dirs==inferred,'projection target has untracked empty/different directory structure');check(deadline);return sorted(rows,key=lambda r:r['path'])
def _projection_git_generation(root,inventory,deadline,process):
    """Only Git built-in read queries, with the measured work tree explicit."""
    root=Path(root);require(root.resolve(strict=True)==root and root.is_dir(),'canonical projection project work tree required')
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','GIT_ALLOW_PROTOCOL':'','GIT_WORK_TREE':str(root)}
    check(deadline);args=['rev-parse','HEAD','HEAD^{tree}']
    try:
        result=process.run_bounded(['/usr/bin/git',*GIT_PACK_OPTIONS,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','maintenance.auto=false','-C',str(root),*args],timeout_seconds=min(30,deadline-time.monotonic()),maximum_output=1024,env=env)
    except process.BoundedProcessError as error:
        raise SourceError(git_query_failure('actual projection Git capture failed',str(root),root,args,error)) from error
    require(result.returncode==0,git_query_failure('actual projection Git query failed',str(root),root,args,result))
    require(result.stdout==(inventory['head']+'\n'+inventory['tree']+'\n').encode(),'physical projection checkout is not the selected private/original generation');check(deadline);return result.stdout
def collect_manifest_projections(view,manifest_raw,inventories,candidate,deadline):
    view=Path(view);require(view.is_absolute() and view.resolve(strict=True)==view and view.is_dir(),'canonical actual merged projection view required');rows=[];old_view=view.lstat();process=bounded_module(deadline);declared=manifest_projections(manifest_raw);generations={}
    for project in sorted({r['project'] for r in declared}):
        root=view/project;raw=_projection_git_generation(root,inventories[project],deadline,process);generations[project]=dict(physical_work_tree=str(root),raw_before_base64=base64.b64encode(raw).decode())
    for declaration in declared:
        check(deadline);directory,expected=projected_source_rows(declaration,inventories);destination=view/declaration['destination'];source=view/declaration['project']/declaration['source'];old=destination.lstat();target=None
        if declaration['kind']=='linkfile':
            require(stat.S_ISLNK(old.st_mode),'actual manifest link destination absent');target=os.readlink(destination);resolved=posixpath.normpath(posixpath.join(posixpath.dirname(declaration['destination']),target));require(not target.startswith('/') and resolved==declaration['project']+'/'+declaration['source'],'actual manifest link target redirects');observed='symlink';actual=source
        else:require(stat.S_ISREG(old.st_mode),'actual manifest copy not ordinary');observed='regular';actual=destination
        before=_projection_target_snapshot(actual,deadline,directory);after=_projection_target_snapshot(actual,deadline,directory);require(before==after==expected,'actual projection destination/source full contents differ');require(identity(destination.lstat())==identity(old) and (target is None or os.readlink(destination)==target),'projection destination link/file identity changed')
        rows.append(dict(declaration,observed_kind=observed,symlink_target=target,actual_target_files=after,target_file_inventory_complete=True,before_target_inventory_sha256=sha(canonical(before)),after_target_inventory_sha256=sha(canonical(after))))
    for project,observation in generations.items():observation['raw_after_base64']=base64.b64encode(_projection_git_generation(view/project,inventories[project],deadline,process)).decode()
    require(identity(view.lstat())==identity(old_view),'physical projection view root changed during observation')
    result=dict(schema='org.trillionnium.owner-manifest-projection-observations.v1',source_commit=candidate['commit'],source_tree=candidate['tree'],source_archive_sha256=candidate['archive_sha256'],resolved_manifest_sha256=sha(manifest_raw),physical_view_root=str(view),project_git_observations=generations,projections=rows,complete=True,observations_sequential_not_globally_atomic=True,source_bom_qualified=False);validate_projections(result,candidate,manifest_raw,inventories);check(deadline);return result
def check_tuple(value,candidate):
    require((value.get('source_commit'),value.get('source_tree'),value.get('source_archive_sha256'))==(candidate['commit'],candidate['tree'],candidate['archive_sha256']),'document candidate tuple differs')

def validate_candidate(candidate):
    exact(candidate,('commit','tree','archive_sha256','control_regular_files'),'candidate')
    hexvalue(candidate['commit'],HEX40,'candidate commit');hexvalue(candidate['tree'],HEX40,'candidate tree');hexvalue(candidate['archive_sha256'],HEX64,'candidate archive')
    require(type(candidate['control_regular_files']) is int and 0<candidate['control_regular_files']<=250000,'exact candidate control source count required')
    return candidate

def validate_custody(value,candidate):
    validate_candidate(candidate)
    require(value.get('schema')=='org.trillionnium.audit.frozen-candidate-custody.v1' and value.get('source_commit')==candidate['commit'] and value.get('source_tree')==candidate['tree'],'actual canonical custody tuple differs')
    require(value.get('tracked_files_verified')==candidate['control_regular_files'] and type(value.get('tracked_files_verified')) is int and value.get('every_archive_file_matches_tested_frozen_git_blob') is True,'actual custody count/blob closure missing')
    archive=value.get('source_archive');require(type(archive) is dict and archive.get('sha256')==candidate['archive_sha256'] and type(archive.get('bytes')) is int and 0<archive['bytes']<=128*1024*1024,'canonical custody archive differs')
    return value
def _asb_catalog_helper(deadline):
    path=Path(__file__).with_name('owner_asb_fork_catalog.py')
    raw=read_stable(path,256*1024,deadline);require(sha(raw)==ASB_CATALOG_HELPER_SHA,'pinned exact fork catalog helper changed')
    spec=importlib.util.spec_from_file_location('owner_asb_catalog',path);m=importlib.util.module_from_spec(spec)
    exec(compile(raw,str(path),'exec'),m.__dict__)
    require(read_stable(path,256*1024,deadline)==raw,'retained catalog helper moved during compile/exec');return m

def validate_asb_fork_binding(value,candidate,inventories,deadline):
    # All nested raw proofs enter the unchanged 2GiB whole metadata budget.
    check(deadline);cat=_asb_catalog_helper(deadline);fixed={};metadata_bytes=0
    def read(desc,maximum):
        nonlocal metadata_bytes
        raw=inventories.read(desc,maximum) if isinstance(inventories,InventoryStore) else read_descriptor(desc,deadline,maximum)
        key=desc['path'];require(key not in fixed or fixed[key][0]==desc,'fork evidence path assigned conflicting descriptor')
        if key not in fixed:metadata_bytes+=len(raw);require(metadata_bytes<=MAX_GRAPH_METADATA,'fork receipt/raw inventories whole metadata bound')
        fixed[key]=(desc,maximum,raw);return raw
    receipt=parse(read(value['asb24_fullfork_receipt'],32*1024*1024));catalog_raw=read(receipt['catalog_descriptor'],128*1024*1024)
    require(sha(catalog_raw)==ASB_CATALOG_SHA==receipt.get('catalog_sha256'),'current exact catalog source differs');catalog=cat.validate_catalog(cat.parse(catalog_raw))
    evidence=receipt.get('scoped_evidence_descriptors');require(type(evidence) is list and len(evidence)==len(catalog['scoped_evidence']),'all declared scoped witness descriptors required')
    for spec,desc in zip(catalog['scoped_evidence'],evidence):
        require(desc['path']==receipt['stage']+'/control/'+spec['canonical_path'] and desc['bytes']==spec['bytes'] and desc['sha256']==spec['sha256'],'scoped witness descriptor canonical mapping differs');read(desc,cat.MAX_FILE)
    if inventories is not None:
        cat.validate_control_catalog(catalog,catalog_raw,inventories['trillionnium-os'])
    def read_inventory(desc):
        inv=parse(read(desc,128*1024*1024));validate_inventory(inv);return inv
    source4=cat.validate_source4_baselines(parse(read(receipt['source4_composition_descriptor'],8*1024*1024)),parse(read(receipt['source4_defensive_descriptor'],8*1024*1024)),candidate)
    cat.validate_fork_receipt(receipt,candidate,catalog,read_inventory,lambda d:parse(read(d,128*1024*1024)),inventories,source4)
    rows={r['path']:r for r in value['private_projects']}
    for r in receipt['projects']:
        require((rows[r['path']]['private_head'],rows[r['path']]['private_tree'],rows[r['path']]['private_repository'])==(r['private_head'],r['private_tree'],r['private_repository']),'final composition substitutes another complete fork')
    for desc,maximum,raw in fixed.values():require(read_descriptor(desc,deadline,maximum)==raw,'nested complete fork evidence moved')
    check(deadline);return [x[0] for x in fixed.values()]

def validate_composition(value,candidate,manifest_raw,inventories,private_paths,manifest_inventory=None,deadline=None):
    if deadline is None:deadline=time.monotonic()+1800
    validate_private_paths(private_paths)
    require(value.get('schema')=='org.trillionnium.audit.actual-exact-private-android-source-binding.v2','actual final38 private composition receipt required');check_tuple(value,candidate)
    require(value.get('actual_refreshed13_composition_candidate_bound') is True and value.get('actual_asb24_fullfork_candidate_bound') is True and value.get('private_project_count')==PRIVATE_COUNT and type(value.get('private_project_count')) is int and value.get('private1170_static_manifest_sha256')==sha(manifest_raw),'actual final38/private1170 composition tuple differs')
    rows=value.get('private_projects');require(type(rows) is list and len(rows)==PRIVATE_COUNT,'actual38 private repository generation bindings missing');seen=set()
    for row in rows:
        project=relative(row.get('path'));require(project in private_paths and project not in seen,'private composition namespace differs');seen.add(project);require(row.get('private_head')==inventories[project]['head'] and row.get('private_tree')==inventories[project]['tree'],'actual private generation differs from full measured inventory')
        require(type(row.get('private_repository')) is str and Path(row['private_repository']).is_absolute(),'actual private physical repository binding missing')
    require(seen==set(private_paths),'private composition whole38 set differs')
    if manifest_inventory is not None:require(value.get('manifest_head')==manifest_inventory['head'] and value.get('manifest_tree')==manifest_inventory['tree'],'actual final private manifest repository generation differs')
    for name in ('source_bom_qualified','independent_migration_approval_asserted','canonical_source_authority_modified','installed','release_qualified'):require(value.get(name) is False,'private composition receipt exceeds precursor scope')
    validate_asb_fork_binding(value,candidate,inventories,deadline)
    return value

def _publish_new(directory,name,raw,deadline):
    """New inode + exclusive atomic link, only in a private owned directory."""
    import secrets
    directory=Path(directory);require(directory.is_absolute() and directory.resolve(strict=True)==directory,'canonical private publish directory required');old=directory.lstat()
    require(stat.S_ISDIR(old.st_mode) and old.st_uid==os.geteuid() and not old.st_mode&0o077,'private owned publish directory required')
    require(type(name) is str and name and '/' not in name and '\\' not in name and len(name)<=128,'publish filename syntax')
    parent=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC);temp='.owner-bom-'+secrets.token_hex(16);linked=False
    try:
        held=os.fstat(parent);require((held.st_dev,held.st_ino,held.st_mode,held.st_uid)==(old.st_dev,old.st_ino,old.st_mode,old.st_uid),'publish parent moved before open')
        with io.FileIO(os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=parent),'wb',closefd=True) as f:
            offset=0
            while offset<len(raw):check(deadline);n=f.write(raw[offset:offset+1024*1024]);require(type(n) is int and n>0,'private inode short write');offset+=n
            check(deadline);f.flush();os.fsync(f.fileno());check(deadline)
        current=directory.lstat();require((current.st_dev,current.st_ino,current.st_mode,current.st_uid)==(old.st_dev,old.st_ino,old.st_mode,old.st_uid),'publish parent path moved')
        os.link(temp,name,src_dir_fd=parent,dst_dir_fd=parent,follow_symlinks=False);linked=True;os.unlink(temp,dir_fd=parent);os.fsync(parent);check(deadline)
        result=descriptor(directory/name,raw);require(read_descriptor(result,deadline)==raw,'new published inode custody differs');return result
    finally:
        if not linked:
            try:os.unlink(temp,dir_fd=parent)
            except FileNotFoundError:pass
        # Standalone observer boundary: raw directory FD close is attempted
        # once. Arbitrary asynchronous close interruption is not a guarantee.
        os.close(parent)

def publish_sharded_inventory(project,inventory,directory,deadline):
    project=relative(project);validate_inventory(inventory);rows=inventory['source_files'];require(len(canonical(rows))<=128*1024*1024,'single-project measured metadata bound')
    raw_tree=decode64(inventory['raw_ls_tree_base64'],32*1024*1024,'ls-tree');raw_descriptor=_publish_new(directory,'raw-ls-tree.bin',raw_tree,deadline)
    shards=[];chunk=[];chunk_bytes=0
    def publish_chunk():
        value=dict(schema='org.trillionnium.owner-git-content-shard.v1',project=project,rows=chunk)
        raw=canonical(value);require(len(raw)<=8*1024*1024,'source shard actual byte bound');desc=_publish_new(directory,'source-shard-'+str(len(shards)).zfill(5)+'.json',raw,deadline);shards.append(dict(descriptor=desc,rows=len(chunk)))
    for row in rows:
        check(deadline);size=len(canonical(row))
        if chunk and (len(chunk)>=4096 or chunk_bytes+size>4*1024*1024):publish_chunk();chunk=[];chunk_bytes=0
        chunk.append(row);chunk_bytes+=size
    if chunk:publish_chunk()
    metadata={k:v for k,v in inventory.items() if k not in ('source_files','raw_ls_tree_base64')}
    record=dict(schema='org.trillionnium.owner-git-content-indexed-record.v1',project=project,source_file_count=len(rows),metadata=metadata,raw_ls_tree=raw_descriptor,source_file_shards=shards)
    return _publish_new(directory,'project-content-record.json',canonical(record),deadline)

class InventoryStore(dict):
    """Bound per-project proof loading; preserve every raw fragment descriptor."""
    def __init__(self,index,candidate,manifest_raw,private_paths,deadline):
        require(index.get('schema')=='org.trillionnium.owner-git-content-index.v1' and index.get('profile_id')==PROFILE,'distinct owner inventory index required')
        require(index.get('candidate')==candidate and index.get('resolved_manifest_sha256')==sha(manifest_raw),'inventory index tuple/manifest splice')
        entries=index.get('projects');require(type(entries) is list and len(entries)==MANIFEST_COUNT,'whole1170 inventory descriptor index required')
        super().__init__();self.deadline=deadline;self.retain=set(private_paths)|{'trillionnium-os'};self.cache={};self.proofs={};self.fixed={};self.fixed_limits={};self.fixed_path_bytes=0;self.file_count=0;self.metadata_bytes=0;self.source_bytes=0;self.retained_files=0;self.retained_bytes=0;self.links=[];self.link_bytes=0
        for entry in entries:
            exact(entry,('project','record'),'project inventory index entry');name=relative(entry['project']);require(name not in self,'duplicate project inventory index');dict.__setitem__(self,name,entry['record'])
        require(set(self)==set(parse_manifest(manifest_raw)),'inventory index project namespace differs from full manifest')
    def read(self,desc,maximum):
        raw=read_descriptor(desc,self.deadline,maximum);key=desc['path'];require(key not in self.fixed or self.fixed[key]==desc,'one descriptor path assigned different custody')
        if key not in self.fixed:
            self.fixed_path_bytes+=len(key.encode());self.fixed_limits[key]=maximum;self.metadata_bytes+=len(raw);require(self.metadata_bytes<=MAX_GRAPH_METADATA,'whole unique raw source evidence byte boundary')
        self.fixed[key]=desc;require(len(self.fixed)<=100000 and self.fixed_path_bytes<=32*1024*1024,'whole raw evidence descriptor bound');return raw
    def __getitem__(self,project):
        if project in self.cache:return self.cache[project]
        record=parse(self.read(dict.__getitem__(self,project),8*1024*1024));exact(record,('schema','project','source_file_count','metadata','raw_ls_tree','source_file_shards'),'indexed project record')
        require(record['schema']=='org.trillionnium.owner-git-content-indexed-record.v1' and record['project']==project,'project record namespace splice')
        count=record['source_file_count'];require(type(count) is int and 0<=count<=250000,'project source count bound');rows=[];raw_total=0
        shards=record['source_file_shards'];require(type(shards) is list and len(shards)<=250000,'project shard count bound')
        for part in shards:
            check(self.deadline);exact(part,('descriptor','rows'),'source shard index');require(type(part['rows']) is int and 0<part['rows']<=4096,'source shard row bound');raw=self.read(part['descriptor'],8*1024*1024);raw_total+=len(raw);require(raw_total<=128*1024*1024,'single-project source metadata bound');value=parse(raw)
            exact(value,('schema','project','rows'),'source shard');require(value['schema']=='org.trillionnium.owner-git-content-shard.v1' and value['project']==project and type(value['rows']) is list and len(value['rows'])==part['rows'],'source shard namespace/count differs');rows.extend(value['rows']);require(len(rows)<=count,'source shard aggregate count exceeded')
        require(len(rows)==count,'source shard aggregate incomplete');raw_tree=self.read(record['raw_ls_tree'],32*1024*1024);metadata=record['metadata'];require(type(metadata) is dict and 'source_files' not in metadata and 'raw_ls_tree_base64' not in metadata,'indexed metadata duplicates source fields');value=dict(metadata,source_files=rows,raw_ls_tree_base64=base64.b64encode(raw_tree).decode());validate_inventory(value)
        digest=sha(canonical(value));require(project not in self.proofs or self.proofs[project]==digest,'project evidence changed on reload')
        if project not in self.proofs:
            self.file_count+=len(rows);self.source_bytes+=value['source_bytes'];require(self.file_count<=MAX_GRAPH_FILES and self.metadata_bytes<=MAX_GRAPH_METADATA and self.source_bytes<=128*1024**3,'whole graph file/metadata/content bounds');self.proofs[project]=digest
            for row in rows:
                if row['git_mode']=='120000':
                    name=project+'/'+row['path'];self.links.append((name,row['symlink_target']));self.link_bytes+=len(name.encode())+len(row['symlink_target'].encode());require(len(self.links)<=100000 and self.link_bytes<=8*1024*1024,'whole source symlink evidence bound')
            if project in self.retain:
                self.retained_files+=len(rows);self.retained_bytes+=raw_total;require(self.retained_files<=MAX_RETAINED_FILES and self.retained_bytes<=MAX_RETAINED_METADATA,'selected private source retained-memory boundary');self.cache[project]=value
        check(self.deadline);return value
    def items(self):
        for project in dict.__iter__(self):yield project,self[project]
    def values(self):
        for _,value in self.items():yield value
    def check_links(self,projections=()):
        # Reload only the target project as needed, rather than holding all
        # 1170 path dictionaries in memory. The same deadline and descriptors
        # remain binding; unknown non-Git/generated targets stay held.
        for start,target in list(self.links):
            current=start;seen=set()
            for _ in range(40):
                check(self.deadline);require(current not in seen,'cyclic tracked source symlink');seen.add(current);require(target and not target.startswith('/') and '\\' not in target and not any(ord(c)<32 for c in target),'unsafe tracked source symlink');current=posixpath.normpath(posixpath.join(posixpath.dirname(current),target));require(current!='..' and not current.startswith('../'),'tracked source symlink escapes graph')
                current=map_projection_path(current,projections,self);projects=[p for p in self if current==p or current.startswith(p+'/')];require(projects,'tracked source symlink project unavailable');project=max(projects,key=len);path=current[len(project):].lstrip('/');inv=self[project];matches=[r for r in inv['source_files'] if r['path']==path]
                require(not any(path==r['path'] or path.startswith(r['path']+'/') for r in inv['gitlinks']),'unmaterialized gitlink is not an available source link target')
                if not matches:require(not path or any(r['path'].startswith(path+'/') for r in inv['source_files']),'tracked source symlink target unavailable');break
                row=matches[0]
                if row['git_mode']!='120000':break
                target=row['symlink_target']
            else:raise SourceError('source symlink chain limit')
    def reverify(self):
        for key,desc in self.fixed.items():self.read(desc,self.fixed_limits[key])
        check(self.deadline)
def vector(value,candidate,manifest,expected_paths):
    require(value.get('schema')==VECTOR_SCHEMA and value.get('complete') is True,'complete owner raw observation vector required')
    check_tuple(value,candidate);rows=value.get('projects');require(type(rows) is list,'vector rows unavailable')
    by={}
    for row in rows:
        path=relative(row.get('path'));require(path not in by and path in manifest,'duplicate/unknown vector project');by[path]=row
        require(row.get('query_resolved') is True and row.get('head')==manifest[path]['revision'],'unknown/mismatched source query')
        hexvalue(row.get('tree'),HEX40,'vector tree');raw=decode64(row.get('raw_git_status_base64'),8*1024*1024,'vector status')
        require(type(row.get('git_status_bytes')) is int and row['git_status_bytes']==len(raw) and row.get('git_status_sha256')==sha(raw),'raw source vector status custody differs')
    require(set(by)==expected_paths,'incomplete vector project set');return by

def source_link_closure(inventories,projections=()):
    entries={};directories={''};gitlinks=set()
    for project,inv in inventories.items():
        gitlinks.update(project+'/'+r['path'] for r in inv['gitlinks'])
        for row in inv['source_files']:
            name=project+'/'+row['path'];require(name not in entries,'overlapping manifest source namespaces');entries[name]=row
            parent=posixpath.dirname(name)
            while parent:
                directories.add(parent);parent=posixpath.dirname(parent)
    for name,row in entries.items():
        if row['git_mode']!='120000':continue
        current=name;seen=set()
        for _ in range(40):
            require(current not in seen,'cyclic tracked source symlink');seen.add(current);link=entries[current]['symlink_target']
            require(link and not link.startswith('/') and '\\' not in link and not any(ord(c)<32 for c in link),'unsafe tracked source symlink')
            current=posixpath.normpath(posixpath.join(posixpath.dirname(current),link));current=map_projection_path(current,projections,inventories)
            require(not any(current==name or current.startswith(name+'/') for name in gitlinks),'unmaterialized gitlink is not an available source link target')
            require(current!='..' and not current.startswith('../') and (current in entries or current in directories),'source symlink unavailable or escapes complete graph')
            if current in directories or entries[current]['git_mode']!='120000':break
        else:raise SourceError('source symlink chain bound')

def validate_selection(selection,candidate,inventories):
    require(selection.get('schema')=='org.trillionnium.owner-semantic-source-selection.v1' and selection.get('complete') is True,'actual owner source selection unavailable');check_tuple(selection,candidate)
    require(selection.get('selected_role_counts')=={'codex':1,'owner_host':1,'owner_core':1,'provider_adapter':1},'owner single-runtime roles differ')
    require(selection.get('legacy_role_counts')=={r:0 for r in LEGACY_ROLES},'legacy role exclusion missing/different')
    require(selection.get('scope')=='source_only_not_compiled_or_installed' and selection.get('measured_source_graph') is True,'owner selection source measurement missing')
    require(type(selection.get('checker_returncode')) is int and selection['checker_returncode']==0,'actual source checker kernel exit must be zero')
    raw=decode64(selection.get('checker_stdout_base64'),2*1024*1024,'source checker stdout');require(sha(raw)==selection.get('checker_stdout_sha256'),'source checker capture digest differs')
    parsed=parse(raw);require(parsed.get('ok') is True and parsed.get('errors')==[],'owner source checker rejects source closure')
    facts=parsed.get('facts');require(type(facts) is dict and facts.get('claim_ceiling')=='ANDROID_OWNER_OPEN_SOURCE_CLOSURE_PASSED_NOT_COMPILED' and facts.get('automatic_effect_redispatch') is False,'source checker fact contract differs')
    for key in ('soong_compiled','selinux_compiled','target_files_built','image_included','physical_device_observed','public_release'):require(facts.get(key) is False,'source checker exceeds source scope')
    sdk=facts.get('sdk_selection');require(type(sdk) is dict and sdk.get('owner_old_static_and_feature_edges_absent') is True and sdk.get('owner_bool_unconditional_restricted_product_statement_verified') is True,'SDK owner source selector unavailable')
    source_inputs=selection.get('source_inputs');require(type(source_inputs) is list and len(source_inputs)>=4,'owner source selection input closure missing')
    seen=set();control={r['path']:r for r in inventories['trillionnium-os']['source_files']}
    for item in source_inputs:
        project=relative(item.get('project'));path=relative(item.get('path'));key=(project,path);require(key not in seen and project in inventories,'owner selection input project duplicated/unknown');seen.add(key)
        match=[r for r in inventories[project]['source_files'] if r['path']==path]
        require(len(match)==1 and match[0]['sha256']==item.get('sha256') and match[0]['git_blob']==item.get('git_blob'),'owner source selection input not measured exact blob')
    require(('trillionnium-os',SOURCE_CHECKER) in seen and ('trillionnium-os',SDK_CHECKER) in seen and control[SOURCE_CHECKER]['sha256']==SOURCE_CHECKER_SHA and control[SDK_CHECKER]['sha256']==SDK_CHECKER_SHA,'pinned owner semantic source checkers missing/different')
    # Every owned Android working-tree overlay byte must be present in its
    # corresponding private project. Unmapped overlay inputs cannot be waived.
    overlay={}
    for row in control.values():
        prefix='android-integration/working-tree/'
        if row['path'].startswith(prefix):
            merged=row['path'][len(prefix):];matches=[p for p in inventories if merged.startswith(p+'/')]
            require(matches,'owned overlay has no manifest project');project=max(matches,key=len);local=merged[len(project)+1:]
            require((project,local) not in overlay,'duplicate mapped overlay');overlay[(project,local)]=row
    require(overlay,'owner actual overlay closure unavailable')
    for (project,path),row in overlay.items():
        found=[r for r in inventories[project]['source_files'] if r['path']==path]
        require(len(found)==1 and all(found[0][k]==row[k] for k in ('bytes','sha256','git_mode','git_blob')),'actual private project differs from owned Android overlay')
    require(selection.get('actual_overlay_files')==len(overlay),'actual owner overlay scope/count differs')

def validate_graph(candidate,manifest_raw,inventories,before,after,private_paths,manifest_inventory,motorola,generated,selection,archive_report,canonical_custody,projections,private_composition,deadline=None):
    if deadline is None:deadline=time.monotonic()+1800
    validate_candidate(candidate);validate_custody(canonical_custody,candidate)
    manifest=parse_manifest(manifest_raw);require(manifest['trillionnium-os']['revision']==candidate['commit'],'whole control not current candidate')
    require(type(private_paths) is list,'v4 exact38 private project list required')
    private=validate_private_paths(private_paths);require(private<=set(manifest) and 'trillionnium-os' not in private,'private scope overlaps/escapes manifest')
    excluded=private|{'trillionnium-os'};original=set(manifest)-excluded
    require(len(original)==ORIGINAL_COUNT,'v4 exact1131 original source namespace required')
    b=vector(before,candidate,manifest,original);a=vector(after,candidate,manifest,original)
    require(before.get('resolved_manifest_sha256')==after.get('resolved_manifest_sha256')==sha(manifest_raw),'before/after exact manifest custody missing/different')
    require(all((b[p]['head'],b[p]['tree'],b[p]['git_status_sha256'])==(a[p]['head'],a[p]['tree'],a[p]['git_status_sha256']) for p in original),'before/after source generation differs')
    require(type(inventories) in (dict,InventoryStore) and set(inventories)==set(manifest),'all1170 actual Git content inventories required')
    for path,inv in inventories.items():
        validate_inventory(inv);require(inv['head']==manifest[path]['revision'],'inventory/manifest revision differs')
        if path in a:
            require(inv['tree']==a[path]['tree'],'inventory/vector Git tree differs')
            observed=decode64(inv['raw_status_before_base64'],8*1024*1024,'inventory status');lfs={r['path'] for r in inv['source_files'] if r['lfs'] is not None}
            for observation in (b[path],a[path]):
                raw_status=decode64(observation['raw_git_status_base64'],8*1024*1024,'vector status');missing={r['path'] for r in inv['gitlinks'] if r['worktree_before']['state']=='missing'};validate_status(raw_status,lfs,missing);require(raw_status==observed,'vector/actual content status differs')
    validate_projections(projections,candidate,manifest_raw,inventories);declarations=manifest_projections(manifest_raw)
    if type(inventories) is InventoryStore:inventories.check_links(declarations)
    else:source_link_closure(inventories,declarations)
    control=inventories['trillionnium-os'];count=candidate['control_regular_files'];require(control['tree']==candidate['tree'] and len(control['source_files'])==count,'whole candidate control tree/count required')
    require(archive_report.get('all_archive_bytes_match_measured_git_tree') is True and archive_report.get('sha256')==candidate['archive_sha256'] and archive_report.get('regular_files')==count,'actual control archive closure required')
    validate_inventory(manifest_inventory)
    validate_composition(private_composition,candidate,manifest_raw,inventories,private,manifest_inventory,deadline)
    manifest_files=[r for r in manifest_inventory['source_files'] if r['path']=='trillionnium-fogos.xml']
    require(len(manifest_files)==1 and manifest_files[0]['sha256']==sha(manifest_raw),'private manifest Git content not exact resolved XML')
    require(type(motorola) is list and len(motorola)==2,'two Motorola blob-tree observations required')
    trees={}
    for tree in motorola:
        require(tree.get('schema')=='org.trillionnium.owner-non-git-content-tree.v1' and tree.get('complete') is True,'complete measured non-Git tree required')
        path=relative(tree.get('path'));require(path in MOTOROLA_PATHS and path not in trees,'Motorola tree scope differs');trees[path]=tree
        require(tree.get('before_inventory_sha256')==tree.get('after_inventory_sha256')==sha(canonical(tree.get('entries'))),'Motorola before/after content inventory differs')
        entries=tree.get('entries');require(type(entries) is list and entries,'empty/nonmeasured Motorola tree held')
        seen=set()
        for row in entries:
            require(row.get('kind') in ('regular','directory'),'unsupported Motorola special/symlink source held');p=relative(row.get('path'));require(p not in seen,'duplicate Motorola entry');seen.add(p)
            hexvalue(row.get('sha256'),HEX64,'Motorola content');require(type(row.get('bytes')) is int and 0<=row['bytes']<=2*1024**3 and type(row.get('mode')) is int and row['mode']&0o400 and not row['mode']&0o7022,'Motorola file mode/byte boundary')
            if row['kind']=='directory':require(row['bytes']==0 and row['sha256']==sha(b''),'Motorola directory identity shape')
        require(len(entries)<=250000 and sum(r['bytes'] for r in entries)<=16*1024**3,'Motorola complete tree limits')
    require(set(trees)==MOTOROLA_PATHS,'Motorola full tree set differs')
    require(generated.get('schema')=='org.trillionnium.owner-generated-source-delta.v1' and generated.get('complete') is True,'actual generated/ignored/upper source delta missing');check_tuple(generated,candidate)
    require(generated.get('entries')==[] and generated.get('unavailable_paths')==[] and generated.get('source_content_inventory_complete') is True,'generated/unknown source held until explicit origin and input contract')
    validate_selection(selection,candidate,inventories)
    proofs={p:inventories.proofs[p] for p in sorted(inventories)} if type(inventories) is InventoryStore else {p:sha(canonical(v)) for p,v in sorted(inventories.items())}
    return dict(schema=BOM_SCHEMA,profile_id=PROFILE,decision='PASS_MEASURED_OWNER_GRAPH',candidate=candidate,manifest_sha256=sha(manifest_raw),manifest_project_count=MANIFEST_COUNT,private_project_paths=sorted(private),control_regular_files=count,git_content_inventory_sha256=proofs,canonical_custody_sha256=sha(canonical(canonical_custody)),manifest_repository_inventory_sha256=sha(canonical(manifest_inventory)),motorola_tree_inventory_sha256={p:sha(canonical(v)) for p,v in sorted(trees.items())},generated_source_delta_sha256=sha(canonical(generated)),owner_source_selection_sha256=sha(canonical(selection)),manifest_projection_observations_sha256=sha(canonical(projections)),private_composition_sha256=sha(canonical(private_composition)),authority='local_measured_provenance_not_release_authority',observations_sequential_not_globally_atomic=True,clean_public_source_claim=False,canonical_source_authority_modified=False,bom_migration_approval_asserted=False,independent_human_approval_asserted=False,installed=False,production_ready=False)

def inspect_packet(packet_path,deadline):
    raw=read_stable(packet_path,8*1024*1024,deadline);packet=parse(raw)
    exact(packet,('schema','profile_id','candidate','documents','private_project_paths'),'owner packet')
    require(packet['schema']==INPUT_SCHEMA and packet['profile_id']==PROFILE,'wrong owner profile/schema')
    names={'resolved_manifest','control_archive','inventory_index','canonical_custody','original_before','original_after','manifest_repository_inventory','motorola_blob_trees','generated_source_delta','owner_source_selection','manifest_projections','private_composition'}
    require(type(packet['documents']) is dict and set(packet['documents'])==names,'required actual owner documents unavailable')
    reads={k:read_descriptor(v,deadline) for k,v in packet['documents'].items()};docs={k:parse(v) for k,v in reads.items() if k not in ('resolved_manifest','control_archive')}
    validate_candidate(packet['candidate']);validate_custody(docs['canonical_custody'],packet['candidate'])
    inventories=InventoryStore(docs['inventory_index'],packet['candidate'],reads['resolved_manifest'],packet['private_project_paths'],deadline)
    archive=verify_control_archive(reads['control_archive'],inventories['trillionnium-os'],packet['candidate']['archive_sha256'],packet['candidate']['control_regular_files'],deadline)
    result=validate_graph(packet['candidate'],reads['resolved_manifest'],inventories,docs['original_before'],docs['original_after'],packet['private_project_paths'],docs['manifest_repository_inventory'],docs['motorola_blob_trees'],docs['generated_source_delta'],docs['owner_source_selection'],archive,docs['canonical_custody'],docs['manifest_projections'],docs['private_composition'],deadline)
    # Reopen actual inputs; a descriptor digest is not proof of continued ownership.
    for k,value in packet['documents'].items():require(read_descriptor(value,deadline)==reads[k],'fixed graph input moved')
    require(read_stable(packet_path,8*1024*1024,deadline)==raw,'owner packet moved')
    inventories.reverify();result['raw_project_evidence_descriptors']=list(inventories.fixed.values());result['whole_measured_tracked_files']=inventories.file_count;result['whole_source_metadata_bytes']=inventories.metadata_bytes;result['canonical_custody_sha256']=sha(reads['canonical_custody']);result['manifest_projection_observations_sha256']=sha(reads['manifest_projections']);result['private_composition_sha256']=sha(reads['private_composition'])
    result['input_packet_sha256']=sha(raw);result['input_descriptors']=packet['documents'];result['receipt_id']='sha256:'+sha(canonical(result));check(deadline);return result

def inspect_projection_collection(packet_path,view,deadline):
    raw=read_stable(packet_path,8*1024*1024,deadline);packet=parse(raw);exact(packet,('schema','profile_id','candidate','resolved_manifest','inventory_index','private_composition','private_project_paths'),'projection collection packet')
    require(packet['schema']=='org.trillionnium.owner-projection-collection-input.v1' and packet['profile_id']==PROFILE,'distinct projection collection profile required');validate_candidate(packet['candidate'])
    manifest=read_descriptor(packet['resolved_manifest'],deadline,8*1024*1024);index_raw=read_descriptor(packet['inventory_index'],deadline,8*1024*1024);store=InventoryStore(parse(index_raw),packet['candidate'],manifest,packet['private_project_paths'],deadline)
    composition_raw=read_descriptor(packet['private_composition'],deadline,8*1024*1024);validate_composition(parse(composition_raw),packet['candidate'],manifest,store,packet['private_project_paths'],deadline=deadline)
    result=collect_manifest_projections(view,manifest,store,packet['candidate'],deadline);store.reverify()
    require(read_descriptor(packet['resolved_manifest'],deadline,8*1024*1024)==manifest and read_descriptor(packet['inventory_index'],deadline,8*1024*1024)==index_raw and read_descriptor(packet['private_composition'],deadline,8*1024*1024)==composition_raw and read_stable(packet_path,8*1024*1024,deadline)==raw,'projection collection inputs moved')
    result['input_packet_sha256']=sha(raw);result['input_descriptors']={k:packet[k] for k in ('resolved_manifest','inventory_index','private_composition')};result['raw_project_evidence_descriptors']=list(store.fixed.values());check(deadline);return result

def bound_standalone_memory(mebibytes):
    """An actual per-process address-space limit, only in the CLI observer."""
    require(type(mebibytes) is int and 256<=mebibytes<=4096,'standalone memory boundary requires 256..4096 MiB')
    import resource
    maximum=mebibytes*1024*1024;_,hard=resource.getrlimit(resource.RLIMIT_AS)
    if hard!=resource.RLIM_INFINITY:maximum=min(maximum,hard)
    require(maximum>=256*1024*1024,'existing address-space limit too small');resource.setrlimit(resource.RLIMIT_AS,(maximum,maximum));require(resource.getrlimit(resource.RLIMIT_AS)==(maximum,maximum),'observer address-space limit not applied');return maximum

def main():
    p=argparse.ArgumentParser();sub=p.add_subparsers(dest='mode',required=True)
    c=sub.add_parser('collect-git');c.add_argument('root',type=Path);c.add_argument('head');c.add_argument('tree');c.add_argument('--project',help='logical manifest project label for bounded Git failure diagnostics');c.add_argument('--git-query-seconds',type=float,default=30,help='per-Git query deadline, finite 1..300 seconds, capped by remaining whole deadline')
    t=sub.add_parser('collect-blob-tree');t.add_argument('root',type=Path);t.add_argument('label')
    s=sub.add_parser('shard-inventory');s.add_argument('project');s.add_argument('inventory',type=Path);s.add_argument('directory',type=Path)
    r=sub.add_parser('collect-projections');r.add_argument('packet',type=Path);r.add_argument('view',type=Path)
    g=sub.add_parser('inspect');g.add_argument('packet',type=Path)
    p.add_argument('--seconds',type=float,default=3600);p.add_argument('--memory-mib',type=int,default=1024);a=p.parse_args()
    require(math.isfinite(a.seconds) and 0<a.seconds<=7200,'finite collection budget required');deadline=time.monotonic()+a.seconds
    try:
        if a.mode=='collect-git':validate_git_query_seconds(a.git_query_seconds)
        bound_standalone_memory(a.memory_mib)
        if a.mode=='collect-git':result=collect_git_checkout(a.root,a.head,a.tree,deadline,a.project,a.git_query_seconds)
        elif a.mode=='collect-blob-tree':result=collect_blob_tree(a.root,a.label,deadline)
        elif a.mode=='shard-inventory':result=publish_sharded_inventory(a.project,parse(read_stable(a.inventory,128*1024*1024,deadline)),a.directory,deadline)
        elif a.mode=='collect-projections':result=inspect_projection_collection(a.packet,a.view,deadline)
        else:result=inspect_packet(a.packet,deadline)
    except (SourceError,OSError,TimeoutError,KeyError,TypeError,MemoryError,ValueError) as e:
        result=dict(schema=BOM_SCHEMA,profile_id=PROFILE,decision='HOLD_MISSING_OR_UNPROVEN_OWNER_GRAPH',error_type=type(e).__name__,error=str(e),source_bom_qualified=False,installed=False,production_ready=False);print(canonical(result).decode(),end='');return 2
    body=canonical(result);check(deadline);sys.stdout.write(body.decode());sys.stdout.flush();check(deadline);return 0
if __name__=='__main__':raise SystemExit(main())
