#!/usr/bin/env python3
"""Read-only original1170-minus-private16/control vector with no Git filters.

This collector retains dirty raw status; a content inventory must separately
prove every LFS payload and the graph verifier rejects ordinary dirty source.
No source-BOM, immutable snapshot, build or release qualification is granted.
"""
import argparse,base64,hashlib,importlib.util,io,json,math,os,re,stat,sys,time
from pathlib import Path

SOURCE_SHA='404e050d27d11b91df590d8a894a3c7999057c19785b2230d6809514482fa7d2'
HELPER_SHA='9f9b40baa7855a92bac2e29ca612704ff85516a41b310e2a481c5c3a29923cf5'
META_SHA='9b673e4b5b33ec32f904e70bc098bad09763abd26ba8d7fa9231ff85a2ac2618'
MODULE_SHAS={'owner_source_provenance.py':SOURCE_SHA,'owner_bom_bounded_process.py':HELPER_SHA,'verify_owner_target_files_binding.py':META_SHA}
INPUT_SCHEMA='org.trillionnium.owner-source-vector-input.v1'
STATUS_ARGS=['status','--porcelain=v1','-z','--untracked-files=all','--ignored=matching']

def load_source():
    directory=Path(__file__).resolve().parent
    if not (directory/'owner_source_provenance.py').exists():directory=directory.parent/'tools'
    require=lambda condition:None if condition else (_ for _ in ()).throw(ValueError('pinned vector observer source differs'))
    raws={}
    for name,digest in MODULE_SHAS.items():
        path=directory/name;require(path.resolve(strict=True)==path);old=path.lstat();require(stat.S_ISREG(old.st_mode) and old.st_size<=128*1024)
        with io.FileIO(os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC),'rb',closefd=True) as stream:
            identity=lambda value:(value.st_dev,value.st_ino,value.st_size,value.st_mtime_ns,value.st_ctime_ns,value.st_mode,value.st_uid,value.st_gid,value.st_nlink)
            before=os.fstat(stream.fileno());require(identity(before)==identity(old));raw=stream.read(128*1024+1);after=os.fstat(stream.fileno());entry=path.lstat();require(identity(before)==identity(after)==identity(entry));require(hashlib.sha256(raw).hexdigest()==digest);raws[name]=raw
    # Execute the measured source bytes; neither an unmeasured timestamp .pyc
    # nor a later filesystem read can supply the module body.
    source_path=directory/'owner_source_provenance.py'
    spec=importlib.util.spec_from_file_location('owner_vector_bound_source',source_path);module=importlib.util.module_from_spec(spec)
    exec(compile(raws[source_path.name],str(source_path),'exec'),module.__dict__)
    for name,raw in raws.items():require(module.read_stable(directory/name,128*1024,time.monotonic()+10)==raw)
    return module,directory,raws

def observe_project(module,process,root,project,expected_head,deadline,git_query_seconds=30):
    module.validate_git_query_seconds(git_query_seconds)
    root=Path(root);module.require(root.is_absolute() and root.resolve(strict=True)==root and root.is_dir(),'canonical original source work tree required');before_entry=root.lstat();options=[]
    env={'PATH':'/usr/bin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','GIT_CONFIG_NOSYSTEM':'1','GIT_CONFIG_GLOBAL':'/dev/null','GIT_TERMINAL_PROMPT':'0','GIT_OPTIONAL_LOCKS':'0','GIT_ATTR_NOSYSTEM':'1','GIT_ALLOW_PROTOCOL':'','GIT_WORK_TREE':str(root)}
    def git(args,maximum=1024,allowed=(0,)):
        module.check(deadline)
        try:
            result=process.run_bounded(['/usr/bin/git',*module.GIT_PACK_OPTIONS,'-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','gc.auto=0','-c','maintenance.auto=false','-c','core.attributesFile=/dev/null','-c','credential.helper=',*options,'-C',str(root),*args],timeout_seconds=min(git_query_seconds,deadline-time.monotonic()),maximum_output=maximum,env=env)
        except process.BoundedProcessError as error:
            raise module.SourceError(module.git_query_failure('actual vector Git capture failed',project,root,args,error)) from error
        module.require(result.returncode in allowed,module.git_query_failure('actual vector Git query failed',project,root,args,result));module.check(deadline);return result.stdout
    keys=git(['config','--local','--name-only','--get-regexp',r'^filter\.'],1024*1024,(0,1)).decode().splitlines();filters={'lfs'}
    for key in keys:
        match=re.fullmatch(r'filter\.([A-Za-z0-9_.-]{1,128})\.[A-Za-z0-9_.-]+',key);module.require(match is not None,'unsupported local Git filter key');filters.add(match[1])
    for name in sorted(filters):
        for kind,value in (('clean',''),('smudge',''),('process',''),('required','false')):options+=['-c','filter.'+name+'.'+kind+'='+value]
    top=git(['rev-parse','--show-toplevel'],8192);module.require(top==str(root).encode()+b'\n','vector physical work tree differs')
    generation=git(['rev-parse','HEAD','HEAD^{tree}']);parts=generation.splitlines();module.require(len(parts)==2,'vector generation output shape');head,tree=(part.decode() for part in parts);module.hexvalue(head,module.HEX40,'actual vector head');module.hexvalue(tree,module.HEX40,'actual vector tree');module.require(head==expected_head,'vector actual original checkout revision differs')
    raw=git(STATUS_ARGS,8*1024*1024);module.require(not raw or raw.endswith(b'\0'),'vector status truncated');module.require(git(['rev-parse','HEAD','HEAD^{tree}'])==generation,'vector checkout generation changed during query');module.require(module.identity(root.lstat())==module.identity(before_entry),'vector work tree entry changed');module.check(deadline)
    return dict(path=project,physical_work_tree=str(root),head=head,tree=tree,query_resolved=True,status_query=STATUS_ARGS,raw_git_status_base64=base64.b64encode(raw).decode(),git_status_bytes=len(raw),git_status_sha256=module.sha(raw),raw_generation_base64=base64.b64encode(generation).decode(),git_filters_disabled=True,fsmonitor_and_hooks_disabled=True,query_read_only=True)

def inspect_packet(module,packet_path,deadline,git_query_seconds=30):
    module.validate_git_query_seconds(git_query_seconds)
    raw=module.read_stable(packet_path,8*1024*1024,deadline);packet=module.parse(raw);module.exact(packet,('schema','profile_id','candidate','resolved_manifest','private_composition','original_source_root','original_repository_paths'),'vector input packet');module.require(packet['schema']==INPUT_SCHEMA and packet['profile_id']==module.PROFILE,'distinct vector owner input/profile required');module.validate_candidate(packet['candidate'])
    manifest_raw=module.read_descriptor(packet['resolved_manifest'],deadline,8*1024*1024);manifest=module.parse_manifest(manifest_raw);composition_raw=module.read_descriptor(packet['private_composition'],deadline,8*1024*1024);composition=module.parse(composition_raw);module.require(composition.get('schema')=='org.trillionnium.audit.actual-exact-private-android-source-binding.v1' and composition.get('actual_refreshed13_composition_candidate_bound') is True,'actual final private composition required');module.check_tuple(composition,packet['candidate']);module.require(composition.get('private1170_static_manifest_sha256')==module.sha(manifest_raw) and manifest['trillionnium-os']['revision']==packet['candidate']['commit'],'vector manifest/control composition differs')
    private_rows=composition.get('private_projects');module.require(type(private_rows) is list and len(private_rows)==module.PRIVATE_COUNT and type(composition.get('private_project_count')) is int and composition['private_project_count']==module.PRIVATE_COUNT,'vector private16 scope unavailable');private=set()
    for row in private_rows:
        project=module.relative(row.get('path'));module.require(project not in private and project in manifest and project!='trillionnium-os' and row.get('private_head')==manifest[project]['revision'],'vector private source disposition differs');private.add(project)
    module.validate_private_paths(private)
    source_root=Path(packet['original_source_root']);module.require(source_root.is_absolute() and source_root.resolve(strict=True)==source_root and source_root.is_dir(),'canonical physical original source root required');old_root=source_root.lstat();entries=packet['original_repository_paths'];module.require(type(entries) is list,'actual original physical repository mapping required');original=set(manifest)-private-{'trillionnium-os'};roots={}
    for entry in entries:
        module.exact(entry,('project','root'),'original physical mapping');project=module.relative(entry['project']);module.require(project in original and project not in roots and entry['root']==str(source_root/project),'original physical source namespace differs');roots[project]=entry['root']
    module.require(len(original)==module.ORIGINAL_COUNT and set(roots)==original,'full original1153 source mapping missing/extra');process=module.bounded_module(deadline);rows=[]
    for project in sorted(original):rows.append(observe_project(module,process,roots[project],project,manifest[project]['revision'],deadline,git_query_seconds))
    for name,old in (('resolved_manifest',manifest_raw),('private_composition',composition_raw)):module.require(module.read_descriptor(packet[name],deadline,8*1024*1024)==old,'fixed vector source input moved')
    module.require(module.read_stable(packet_path,8*1024*1024,deadline)==raw and module.identity(source_root.lstat())==module.identity(old_root),'vector packet/original root moved')
    result=dict(schema=module.VECTOR_SCHEMA,profile_id=module.PROFILE,source_commit=packet['candidate']['commit'],source_tree=packet['candidate']['tree'],source_archive_sha256=packet['candidate']['archive_sha256'],resolved_manifest_sha256=module.sha(manifest_raw),private_composition_sha256=module.sha(composition_raw),original_source_root=str(source_root),projects=rows,complete=True,input_packet_sha256=module.sha(raw),input_descriptors={name:packet[name] for name in ('resolved_manifest','private_composition')},external_filters_fsmonitor_hooks_disabled=True,observations_sequential_not_globally_atomic=True,all_original_source_bytes_measured=False,source_bom_qualified=False,independent_human_approval_asserted=False,installed=False,production_ready=False);module.check(deadline);return result

def main():
    q=argparse.ArgumentParser();q.add_argument('packet',type=Path);q.add_argument('--seconds',type=float,default=1800);q.add_argument('--memory-mib',type=int,default=1024);q.add_argument('--git-query-seconds',type=float,default=30,help='per-Git query deadline, finite 1..300 seconds, capped by remaining whole deadline');a=q.parse_args();module,directory,source_raw=load_source();module.require(math.isfinite(a.seconds) and 0<a.seconds<=7200,'finite vector collection deadline required');deadline=time.monotonic()+a.seconds
    try:
        module.validate_git_query_seconds(a.git_query_seconds);module.bound_standalone_memory(a.memory_mib);result=inspect_packet(module,a.packet,deadline,a.git_query_seconds)
        for name,old in source_raw.items():module.require(module.read_stable(directory/name,128*1024,deadline)==old,'pinned vector observer module moved')
    except (module.SourceError,OSError,KeyError,TypeError,TimeoutError,MemoryError,ValueError) as e:
        print(module.canonical(dict(schema=module.VECTOR_SCHEMA,complete=False,error_type=type(e).__name__,error=str(e),source_bom_qualified=False,installed=False,production_ready=False)).decode(),end='');return 2
    body=module.canonical(result);module.check(deadline);sys.stdout.write(body.decode());sys.stdout.flush();module.check(deadline);return 0
if __name__=='__main__':raise SystemExit(main())
