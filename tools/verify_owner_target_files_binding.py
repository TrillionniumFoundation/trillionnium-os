#!/usr/bin/env python3
"""Required owner META provenance and whole-ZIP custody; never write a ZIP.

The binding is a build input projected into META, not a digest of the ZIP
that contains it. The caller separately supplies the actual final ZIP
descriptor, avoiding a self-hash cycle and rejecting a META/ZIP splice.
No old P0 optional-binding behavior or signing/install authority is imported.
"""
from __future__ import annotations
import argparse, hashlib, io, json, math, os, re
from pathlib import Path, PurePosixPath
import stat, struct, sys, time, types, zipfile

PROVENANCE_SOURCE_SHA='6340050e53cc0374c26e7f602c1b9d2bd58c59953bafa4ea7eb6962f06c6ee94'

def _load_measured_provenance():
    """CLI and library use actual sibling bytes, never ambient/cache code.

    Each checker owns its provenance namespace. Callers catching SourceError
    should use checker.p.SourceError (it is also a ValueError).
    """
    path=Path(os.path.abspath(__file__)).with_name('owner_source_provenance.py')
    maximum=128*1024
    def read():
        if path.resolve(strict=True)!=path:raise ValueError('owner provenance source path is not physical')
        before=path.lstat()
        identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_mode,value.st_uid,value.st_gid,value.st_nlink)
        if not stat.S_ISREG(before.st_mode) or not 0<before.st_size<=maximum:raise ValueError('owner provenance source size/type differs')
        with io.FileIO(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb',closefd=True) as stream:
            opened=os.fstat(stream.fileno())
            if identity(opened)!=identity(before):raise ValueError('owner provenance source changed before read')
            raw=stream.read(maximum+1);after=os.fstat(stream.fileno());entry=path.lstat()
            if identity(before)!=identity(after) or identity(after)!=identity(entry) or len(raw)!=before.st_size or hashlib.sha256(raw).hexdigest()!=PROVENANCE_SOURCE_SHA:raise ValueError('owner provenance source differs from pinned bytes')
        return raw
    raw=read();module=types.ModuleType('_owner_meta_measured_provenance');module.__file__=str(path)
    exec(compile(raw,str(path),'exec'),module.__dict__)
    if read()!=raw:raise ValueError('owner provenance source moved on load')
    return module

p=_load_measured_provenance()

SCHEMA='org.trillionnium.owner-android-source-bom-binding.v4'
MEMBER='META/trillionnium-owner-source-bom-binding.json'
AUTHORITY='local_measured_provenance_not_release_authority'
MAX_ZIP=16*1024**3

def validate_bom(raw):
    value=p.parse(raw)
    p.exact(value,('schema','profile_id','decision','candidate','manifest_sha256','manifest_project_count','private_project_paths','control_regular_files','git_content_inventory_sha256','canonical_custody_sha256','manifest_repository_inventory_sha256','motorola_tree_inventory_sha256','generated_source_delta_sha256','owner_source_selection_sha256','manifest_projection_observations_sha256','private_composition_sha256','authority','observations_sequential_not_globally_atomic','clean_public_source_claim','canonical_source_authority_modified','bom_migration_approval_asserted','independent_human_approval_asserted','installed','production_ready','input_packet_sha256','input_descriptors','raw_project_evidence_descriptors','whole_measured_tracked_files','whole_source_metadata_bytes','receipt_id'),'complete owner receipt')
    p.require(value.get('schema')==p.BOM_SCHEMA and value.get('profile_id')==p.PROFILE and value.get('decision')=='PASS_MEASURED_OWNER_GRAPH','qualified owner graph receipt required')
    p.require(value['observations_sequential_not_globally_atomic'] is True,'owner observations cannot claim an atomic global snapshot')
    for key in ('clean_public_source_claim','canonical_source_authority_modified','bom_migration_approval_asserted','independent_human_approval_asserted','installed','production_ready'):
        p.require(value.get(key) is False,'owner receipt exceeds provenance scope: '+key)
    p.require(value.get('authority')==AUTHORITY and value.get('manifest_project_count')==p.MANIFEST_COUNT,'owner receipt profile/count/authority differs')
    identifier=value.get('receipt_id');without=dict(value);without.pop('receipt_id',None)
    p.require(identifier=='sha256:'+p.sha(p.canonical(without)),'owner receipt content identifier differs')
    tuple_=p.validate_candidate(value.get('candidate'));p.require(type(value['control_regular_files']) is int and value['control_regular_files']==tuple_['control_regular_files'],'owner source exact candidate count differs')
    inventories=value['git_content_inventory_sha256'];p.require(type(inventories) is dict and len(inventories)==p.MANIFEST_COUNT and 'trillionnium-os' in inventories,'whole owner source inventory descriptor set absent')
    for path,digest in inventories.items():p.relative(path);p.hexvalue(digest,p.HEX64,'Git inventory')
    paths=value['private_project_paths'];p.require(type(paths) is list,'v4 exact38 private project list required');p.validate_private_paths(paths);p.require(set(paths)<=set(inventories) and 'trillionnium-os' not in paths,'private38 source graph differs')
    p.require(type(value['motorola_tree_inventory_sha256']) is dict and set(value['motorola_tree_inventory_sha256'])==p.MOTOROLA_PATHS,'Motorola descriptor scope differs')
    for digest in value['motorola_tree_inventory_sha256'].values():p.hexvalue(digest,p.HEX64,'Motorola inventory')
    for key in ('manifest_sha256','canonical_custody_sha256','manifest_repository_inventory_sha256','generated_source_delta_sha256','owner_source_selection_sha256','manifest_projection_observations_sha256','private_composition_sha256','input_packet_sha256'):p.hexvalue(value[key],p.HEX64,key)
    names={'resolved_manifest','control_archive','inventory_index','canonical_custody','original_before','original_after','manifest_repository_inventory','motorola_blob_trees','generated_source_delta','owner_source_selection','manifest_projections','private_composition'}
    descriptors=value['input_descriptors'];p.require(type(descriptors) is dict and set(descriptors)==names,'all actual owner input descriptors required')
    for descriptor in descriptors.values():
        p.exact(descriptor,('path','bytes','sha256'),'actual source descriptor');p.require(type(descriptor['bytes']) is int and 0<descriptor['bytes']<=128*1024*1024,'actual source descriptor bytes');p.hexvalue(descriptor['sha256'],p.HEX64,'source descriptor')
    p.require(descriptors['resolved_manifest']['sha256']==value['manifest_sha256'] and descriptors['control_archive']['sha256']==tuple_['archive_sha256'] and descriptors['canonical_custody']['sha256']==value['canonical_custody_sha256'] and descriptors['manifest_projections']['sha256']==value['manifest_projection_observations_sha256'] and descriptors['private_composition']['sha256']==value['private_composition_sha256'],'owner source manifest/archive/custody/projection closure differs')
    raw=value['raw_project_evidence_descriptors'];p.require(type(raw) is list and p.MANIFEST_COUNT<=len(raw)<=100000,'whole raw project evidence descriptors missing/bound')
    seen=set();total_paths=0
    for desc in raw:
        p.exact(desc,('path','bytes','sha256'),'retained raw descriptor');p.require(type(desc['path']) is str and desc['path'] not in seen and type(desc['bytes']) is int and 0<=desc['bytes']<=32*1024*1024,'retained raw descriptor duplicate/byte boundary');seen.add(desc['path']);total_paths+=len(desc['path'].encode());p.hexvalue(desc['sha256'],p.HEX64,'raw evidence')
    p.require(total_paths<=32*1024*1024 and type(value['whole_measured_tracked_files']) is int and value['control_regular_files']<=value['whole_measured_tracked_files']<=p.MAX_GRAPH_FILES and type(value['whole_source_metadata_bytes']) is int and 0<value['whole_source_metadata_bytes']<=p.MAX_GRAPH_METADATA,'whole source observation aggregate limits')
    return value

def materialize_binding(bom_raw, build_inputs):
    bom=validate_bom(bom_raw)
    p.exact(build_inputs,('schema','candidate','resolved_manifest_sha256','owner_source_bom_sha256','stage_id'),'owner build inputs')
    p.require(build_inputs['schema']=='org.trillionnium.owner-android-build-source-inputs.v1' and build_inputs['candidate']==bom['candidate'],'owner build input tuple differs')
    p.require(build_inputs['resolved_manifest_sha256']==bom['manifest_sha256'] and build_inputs['owner_source_bom_sha256']==p.sha(bom_raw),'owner build source input provenance differs')
    p.require(type(build_inputs['stage_id']) is str and re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',build_inputs['stage_id']) is not None,'private ASCII build stage syntax')
    value=dict(schema=SCHEMA,profile_id=p.PROFILE,authority=AUTHORITY,candidate=bom['candidate'],owner_source_bom=dict(schema=p.BOM_SCHEMA,bytes=len(bom_raw),sha256=p.sha(bom_raw),receipt_id=bom['receipt_id']),resolved_manifest_sha256=bom['manifest_sha256'],build_inputs_sha256=p.sha(p.canonical(build_inputs)),build_stage_id=build_inputs['stage_id'])
    value['binding_id']='sha256:'+p.sha(p.canonical(value));return value

def admission(stream):
    stream.seek(0,2);length=stream.tell();p.require(0<length<=MAX_ZIP,'whole ZIP actual byte bound');stream.seek(max(0,length-65557));tail=stream.read(65557)
    offset=tail.rfind(b'PK\x05\x06');p.require(offset>=0 and len(tail)-offset>=22,'ZIP end record missing/truncated')
    _,disk,cd_disk,disk_count,count,size,start,comment=struct.unpack_from('<4s4H2IH',tail,offset)
    end=length-len(tail)+offset;p.require(offset+22+comment==len(tail) and disk==cd_disk==0 and disk_count==count,'unsupported ZIP multidisk/end record')
    boundary=end
    if count==65535 or size==0xffffffff or start==0xffffffff:
        p.require(end>=20,'ZIP64 locator missing');stream.seek(end-20);locator=stream.read(20)
        magic,record_disk,record_offset,disks=struct.unpack('<4sIQI',locator)
        p.require(magic==b'PK\x06\x07' and record_disk==0 and disks==1 and record_offset+56<=end-20,'unsupported ZIP64 locator')
        stream.seek(record_offset);record=stream.read(56);p.require(len(record)==56,'ZIP64 end record truncated')
        magic,record_size,_,_,disk,cd_disk,disk_count,count,size,start=struct.unpack('<4sQ2H2I4Q',record)
        p.require(magic==b'PK\x06\x06' and 44<=record_size<=4096 and record_offset+12+record_size==end-20 and disk==cd_disk==0 and disk_count==count,'unsupported ZIP64 end record')
        boundary=record_offset
    p.require(count<=200000 and size<=128*1024*1024 and size>=46*count and start+size<=boundary,'central directory preallocation bound')
    stream.seek(0)

def canonical_member(name):
    q=PurePosixPath(name.rstrip('/'))
    p.require(type(name) is str and 0<len(name)<=4096 and not name.startswith('/') and '\\' not in name and str(q)==name.rstrip('/') and all(x not in ('.','..') for x in q.parts) and not any(ord(c)<32 or ord(c)==127 for c in name),'unsafe/noncanonical ZIP member')

def inspect_stream(stream,bom_raw,build_inputs,expected_zip,deadline):
    p.exact(expected_zip,('bytes','sha256'),'actual ZIP descriptor');p.require(type(expected_zip['bytes']) is int and 0<expected_zip['bytes']<=MAX_ZIP,'ZIP descriptor byte bound');p.hexvalue(expected_zip['sha256'],p.HEX64,'ZIP')
    expected=materialize_binding(bom_raw,build_inputs);admission(stream)
    with zipfile.ZipFile(stream) as z:
        entries=z.infolist();p.require(entries and len(entries)<=200000 and len({e.filename for e in entries})==len(entries),'duplicate/empty ZIP entry set')
        total=0
        for entry in entries:
            p.check(deadline);canonical_member(entry.filename);total+=entry.file_size
            p.require(total<=128*1024**3,'ZIP expanded aggregate bound')
        selected=[e for e in entries if e.filename==MEMBER];p.require(len(selected)==1,'required unique owner META binding absent')
        entry=selected[0];mode=stat.S_IFMT(entry.external_attr>>16)
        p.require(not entry.is_dir() and not entry.flag_bits&1 and mode in (0,stat.S_IFREG) and 0<entry.file_size<=2*1024*1024,'owner META special/encrypted/byte boundary')
        with z.open(entry) as f:raw=f.read(2*1024*1024+1)
        p.check(deadline);p.require(len(raw)==entry.file_size and p.parse(raw)==expected,'owner META provenance/tuple/build binding differs')
    stream.seek(0);h=hashlib.sha256();size=0
    while True:
        p.check(deadline);block=stream.read(1024*1024)
        if not block:break
        size+=len(block);p.require(size<=MAX_ZIP,'whole ZIP actual byte bound');h.update(block)
    p.require(size==expected_zip['bytes'] and h.hexdigest()==expected_zip['sha256'],'whole ZIP final custody moved/spliced')
    result=dict(schema='org.trillionnium.audit.owner-target-files-source-provenance.v1',candidate=expected['candidate'],profile_id=p.PROFILE,owner_binding_id=expected['binding_id'],owner_binding_bytes=len(raw),owner_binding_sha256=p.sha(raw),owner_source_bom_sha256=p.sha(bom_raw),target_files=dict(bytes=size,sha256=h.hexdigest()),required_owner_meta_binding_verified=True,whole_zip_custody_verified=True,release_signature_verified=False,independent_human_approval_asserted=False,installed=False,production_ready=False)
    p.check(deadline);return result

def inspect_path(path,bom_raw,build_inputs,expected_zip,deadline):
    path=Path(path);p.require(path.is_absolute() and path.resolve(strict=True)==path,'canonical absolute ZIP path required');before=path.lstat();p.require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=MAX_ZIP,'ordinary bounded target-files ZIP required')
    with io.FileIO(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb',closefd=True) as f:
        p.require(p.identity(os.fstat(f.fileno()))==p.identity(before),'ZIP entry moved before open');result=inspect_stream(f,bom_raw,build_inputs,expected_zip,deadline)
        p.require(p.identity(os.fstat(f.fileno()))==p.identity(before) and p.identity(path.lstat())==p.identity(before),'ZIP identity moved while observing')
    p.check(deadline);return result

def stage_binding(bom_path,build_inputs_path,binding_path,meta_directory,deadline):
    """Build-time new META inode; never reopen or modify a target-files ZIP."""
    paths=(bom_path,build_inputs_path,binding_path);raw=[p.read_stable(path,128*1024*1024 if number<2 else 2*1024*1024,deadline) for number,path in enumerate(paths)]
    expected=materialize_binding(raw[0],p.parse(raw[1]));p.require(p.parse(raw[2])==expected,'build input binding is not the exact owner BOM/tuple/stage projection')
    for number,(path,old) in enumerate(zip(paths,raw)):p.require(p.read_stable(path,128*1024*1024 if number<2 else 2*1024*1024,deadline)==old,'owner build input moved before publication')
    descriptor=p._publish_new(meta_directory,Path(MEMBER).name,raw[2],deadline)
    for number,(path,old) in enumerate(zip(paths,raw)):p.require(p.read_stable(path,128*1024*1024 if number<2 else 2*1024*1024,deadline)==old,'owner build input moved during publication')
    result=dict(schema='org.trillionnium.audit.owner-meta-build-publication.v1',candidate=expected['candidate'],owner_binding_id=expected['binding_id'],member=MEMBER,meta_file=descriptor,build_input_descriptors={name:p.descriptor(path,body) for name,path,body in zip(('owner_bom','build_inputs','owner_binding'),paths,raw)},stage_output_only=True,zip_modified=False,release_signature_verified=False,independent_human_approval_asserted=False,installed=False,production_ready=False);p.check(deadline);return result

def stage_main():
    environment=sys.argv[1]=='stage-binding-env';q=argparse.ArgumentParser();q.add_argument('--bom',required=not environment,type=Path);q.add_argument('--build-inputs',required=not environment,type=Path);q.add_argument('--binding',required=not environment,type=Path);q.add_argument('--meta-directory',required=True,type=Path);q.add_argument('--seconds',type=float,default=120);q.add_argument('--memory-mib',type=int,default=1024);a=q.parse_args(sys.argv[2:]);p.require(math.isfinite(a.seconds) and 0<a.seconds<=600,'finite build META publication budget');deadline=time.monotonic()+a.seconds
    try:
        if environment:
            p.require(a.bom is None and a.build_inputs is None and a.binding is None,'owner build environment and CLI inputs cannot be mixed');a.bom=Path(os.environ['TRILLINNIUM_OWNER_SOURCE_BOM_JSON']);a.build_inputs=Path(os.environ['TRILLINNIUM_OWNER_SOURCE_BUILD_INPUTS_JSON']);a.binding=Path(os.environ['TRILLINNIUM_OWNER_SOURCE_BOM_BINDING_JSON'])
        p.bound_standalone_memory(a.memory_mib);result=stage_binding(a.bom,a.build_inputs,a.binding,a.meta_directory,deadline)
    except (p.SourceError,OSError,KeyError,TypeError,TimeoutError,MemoryError,ValueError) as e:
        print(p.canonical(dict(schema='org.trillionnium.audit.owner-meta-build-publication.v1',stage_output_only=True,owner_binding_published=False,error_type=type(e).__name__,error=str(e),zip_modified=False,installed=False,production_ready=False)).decode(),end='');return 2
    body=p.canonical(result);p.check(deadline);sys.stdout.write(body.decode());sys.stdout.flush();p.check(deadline);return 0

def main():
    if sys.argv[1:2] in (['stage-binding'],['stage-binding-env']):return stage_main()
    q=argparse.ArgumentParser();q.add_argument('target_files',type=Path);q.add_argument('bom',type=Path);q.add_argument('build_inputs',type=Path);q.add_argument('zip_descriptor',type=Path);q.add_argument('--seconds',type=float,default=1800);a=q.parse_args()
    p.require(math.isfinite(a.seconds) and 0<a.seconds<=7200,'finite ZIP observer budget required');deadline=time.monotonic()+a.seconds
    try:
        paths=(a.bom,a.build_inputs,a.zip_descriptor);raw=[p.read_stable(x,128*1024*1024,deadline) for x in paths]
        result=inspect_path(a.target_files,raw[0],p.parse(raw[1]),p.parse(raw[2]),deadline)
        for path,old in zip(paths,raw):p.require(p.read_stable(path,128*1024*1024,deadline)==old,'fixed verifier input moved')
    except (p.SourceError,OSError,KeyError,TypeError,TimeoutError,zipfile.BadZipFile) as e:
        print(p.canonical(dict(schema='org.trillionnium.audit.owner-target-files-source-provenance.v1',required_owner_meta_binding_verified=False,whole_zip_custody_verified=False,error_type=type(e).__name__,error=str(e),installed=False,production_ready=False)).decode(),end='');return 2
    body=p.canonical(result);p.check(deadline);sys.stdout.write(body.decode());sys.stdout.flush();p.check(deadline);return 0
if __name__=='__main__':raise SystemExit(main())
