#!/usr/bin/env python3
"""Measured source namespace closure; unknown/ignored/generated input stays held.

This helper does not promote a directory name to source authority. Per-project
files must match complete tracked inventories. Unmaterialized gitlinks retain
commit references and separate missing/empty directory observations; no child
commit content is thereby available or measured. Only Git metadata, the explicit
.repo metadata root and one newly empty read-only build-output boundary are
outside the source-content surface. Extra directories/files/aliases are held.
"""
import hashlib,json,os,stat,time
from pathlib import Path,PurePosixPath

def require(value,message):
    if not value:raise ValueError(message)
def budget(deadline):
    if time.monotonic()>=deadline:raise TimeoutError('whole actual source surface deadline')
def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_uid,s.st_gid,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
def canonical(value):return (json.dumps(value,sort_keys=True,indent=2,allow_nan=False)+'\n').encode()
def digest(value):return hashlib.sha256(canonical(value)).hexdigest()
def parents(names):
    result=set()
    for name in names:
        require(type(name) is str and name and str(PurePosixPath(name))==name and not name.startswith('/') and '..' not in PurePosixPath(name).parts,'canonical known source path')
        parent=PurePosixPath(name).parent
        while str(parent)!='.':result.add(str(parent));parent=parent.parent
    return result

def _walk(root,files,directories,deadline,module,*,hash_contents):
    root=Path(root);require(root.is_absolute() and root.resolve(strict=True)==root,'actual physical source root required')
    unknown=[];observed=[];pending=[(root,'')];metadata=[];regular=0;symlinks=0;seen_dirs=[]
    while pending:
        budget(deadline);path,local=pending.pop();old=path.lstat();require(stat.S_ISDIR(old.st_mode),'ordinary measured source directory required');seen_dirs.append((path,identity(old)))
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            require(identity(os.fstat(fd))==identity(old),'source directory entry/FD moved')
            with os.scandir(fd) as scan:
                for entry in scan:
                    budget(deadline);name=entry.name;relative=(local+'/' if local else '')+name
                    s=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    if relative=='.git':
                        require(stat.S_ISDIR(s.st_mode) or stat.S_ISLNK(s.st_mode) or stat.S_ISREG(s.st_mode),'unsupported Git metadata entry')
                        metadata.append(dict(path=relative,identity=list(identity(s)),link_target=os.readlink(name,dir_fd=fd) if stat.S_ISLNK(s.st_mode) else None));continue
                    row=dict(path=relative,identity=list(identity(s)))
                    if stat.S_ISDIR(s.st_mode):
                        if relative not in directories:unknown.append(dict(path=relative,kind='untracked_or_empty_directory'))
                        row['kind']='directory';pending.append((path/name,relative))
                    elif relative not in files:
                        unknown.append(dict(path=relative,kind='untracked_or_special_entry'));row['kind']='unknown'
                        if stat.S_ISLNK(s.st_mode):row['target']=os.readlink(name,dir_fd=fd)
                    else:
                        expected=files[relative]
                        if expected['git_mode']=='120000':
                            require(stat.S_ISLNK(s.st_mode),'tracked source link replaced');target=os.readlink(name,dir_fd=fd);raw=target.encode()
                            require((len(raw),hashlib.sha256(raw).hexdigest(),target)==(expected['bytes'],expected['sha256'],expected['symlink_target']),'actual source link differs from tracked inventory')
                            row.update(kind='symlink',target=target);symlinks+=1
                        else:
                            require(stat.S_ISREG(s.st_mode),'tracked ordinary source replaced by special/link')
                            require(s.st_size==expected['bytes'] and ('100755' if s.st_mode&0o111 else '100644')==expected['git_mode'],'actual source bytes/mode differs')
                            if hash_contents:
                                actual=module.measure_regular(path/name,2*1024**3,deadline)
                                require((actual['bytes'],actual['sha256'],actual['git_mode'])==(expected['bytes'],expected['sha256'],expected['git_mode']),'actual view source contents differ from collected physical Git tree')
                            row['kind']='regular';regular+=1
                        require(identity(os.stat(name,dir_fd=fd,follow_symlinks=False))==identity(s),'source entry moved during namespace measurement')
                    observed.append(row);require(len(observed)<=500000 and len(unknown)<=500000,'per-project surface entry bound')
            require(identity(os.fstat(fd))==identity(old) and identity(path.lstat())==identity(old),'source directory moved during traversal')
        finally:os.close(fd)
    for directory,expected in seen_dirs:
        budget(deadline);require(identity(directory.lstat())==expected,'source directory changed after earlier traversal')
    budget(deadline);actual={r['path'] for r in observed if r['kind'] in ('regular','symlink')}
    require(actual==set(files),'tracked view source inventory missing/extra')
    return dict(root_identity=list(identity(root.lstat())),entries=sorted(observed,key=lambda r:r['path']),unknown=sorted(unknown,key=lambda r:r['path']),metadata=metadata,regular_files=regular,symlinks=symlinks)

def project_surface(module,root,inventory,deadline):
    module.validate_inventory(inventory);files={r['path']:r for r in inventory['source_files']};refs=inventory['gitlinks'];dirs=parents(set(files)|{r['path'] for r in refs})
    dirs.update(r['path'] for r in refs if r['worktree_before']['state']=='empty')
    refs_before=[module.observe_unmaterialized_gitlink(root,r['path'],deadline) for r in refs]
    before=_walk(root,files,dirs,deadline,module,hash_contents=True);after=_walk(root,files,dirs,deadline,module,hash_contents=False)
    refs_after=[module.observe_unmaterialized_gitlink(root,r['path'],deadline) for r in refs]
    require(refs_before==refs_after,'selected-view gitlink state or FD identity changed')
    for row,actual in zip(refs,refs_before):
        require((actual['state'],actual['absent_path'])==(row['worktree_before']['state'],row['worktree_before']['absent_path']),'selected-view gitlink state differs from physical collector')
    require(before==after,'sequential full source namespace/FD identity changed')
    diagnostic_roots=[]
    for row in after['unknown']:
        if not any(row['path']==known or row['path'].startswith(known+'/') for known in diagnostic_roots):diagnostic_roots.append(row['path'])
    diagnostics=[dict(path=name,actual_diagnostic=unknown_tree(Path(root)/name,deadline)) for name in diagnostic_roots]
    result=dict(schema='org.trillionnium.audit.actual-project-source-surface.v2',root=str(root),head=inventory['head'],tree=inventory['tree'],tracked_files=len(files),gitlink_references=[dict(path=r['path'],git_commit=r['git_commit'],actual_view_worktree=actual,submodule_content_measured=False) for r,actual in zip(refs,refs_before)],actual_regular_files=after['regular_files'],actual_symlinks=after['symlinks'],actual_entry_count=len(after['entries']),before_namespace_sha256=digest(before),after_namespace_sha256=digest(after),git_metadata_entries=after['metadata'],unknown_entries=after['unknown'],unknown_content_diagnostics=diagnostics,complete=True,accepted=not after['unknown'],view_content_hash_matches_physical_collector=True,second_namespace_identity_pass_not_second_content_hash=True,observations_sequential_not_globally_atomic=True,source_bom_qualified=False)
    budget(deadline);return result

def unknown_tree(path,deadline):
    """Bounded diagnostic contents of an unmodeled subtree; always a HOLD."""
    path=Path(path);deadline=min(deadline,time.monotonic()+300);entries=[];total=0;seen_dirs=[];pending=[(path,'')];error=None
    try:
        while pending:
            budget(deadline);current,local=pending.pop();old=current.lstat();kind='directory' if stat.S_ISDIR(old.st_mode) else 'regular' if stat.S_ISREG(old.st_mode) else 'symlink' if stat.S_ISLNK(old.st_mode) else 'special'
            row=dict(path=local,kind=kind,bytes=old.st_size,mode=stat.S_IMODE(old.st_mode),identity=list(identity(old)),sha256=None)
            if kind=='directory':
                seen_dirs.append((current,identity(old)));fd=os.open(current,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    require(identity(os.fstat(fd))==identity(old),'unknown source directory FD moved')
                    with os.scandir(fd) as scan:
                        for entry in scan:
                            budget(deadline);pending.append((current/entry.name,(local+'/' if local else '')+entry.name))
                            require(len(entries)+len(pending)<=100000,'unknown source diagnostic entry bound')
                    require(identity(os.fstat(fd))==identity(old) and identity(current.lstat())==identity(old),'unknown source directory moved')
                finally:os.close(fd)
            elif kind=='regular':
                require(old.st_size<=2*1024**3 and total+old.st_size<=8*1024**3,'unknown source diagnostic byte bound')
                fd=os.open(current,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC);h=hashlib.sha256();count=0
                try:
                    require(identity(os.fstat(fd))==identity(old),'unknown source regular FD moved')
                    while True:
                        budget(deadline);block=os.read(fd,65536)
                        if not block:break
                        count+=len(block);require(count<=old.st_size,'unknown source file grew');h.update(block)
                    require(count==old.st_size and identity(os.fstat(fd))==identity(old) and identity(current.lstat())==identity(old),'unknown source file changed while hashing')
                finally:os.close(fd)
                row['sha256']=h.hexdigest();total+=count
            elif kind=='symlink':
                target=os.readlink(current);raw=target.encode();row.update(target=target,sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw));require(identity(current.lstat())==identity(old),'unknown source alias moved')
            else:row['rdev']=old.st_rdev
            entries.append(row);require(len(entries)<=100000,'unknown source diagnostic entry bound')
        for directory,old in seen_dirs:
            budget(deadline);require(identity(directory.lstat())==old,'unknown source directory changed after earlier traversal')
        budget(deadline)
    except (OSError,ValueError,TimeoutError) as exc:error=dict(type=type(exc).__name__,message=str(exc)[:1024])
    result=dict(schema='org.trillionnium.audit.actual-unknown-source-tree-diagnostic.v1',root=str(path),entries=sorted(entries,key=lambda r:r['path']),regular_bytes_hashed=total,make_source_indicator_paths=sorted(r['path'] for r in entries if PurePosixPath(r['path']).name in {'Android.bp','Android.mk','Makefile'} or r['path'].endswith('.mk')),complete=error is None,error=error,accepted=False,source_origin_or_selection_qualified=False,symlink_targets_followed=False,special_files_opened=False,content_body_exported=False,limits=dict(seconds=300,entries=100000,per_file_bytes=2*1024**3,aggregate_regular_bytes=8*1024**3),source_bom_qualified=False)
    try:budget(deadline)
    except TimeoutError as exc:result.update(complete=False,error=dict(type=type(exc).__name__,message=str(exc)))
    return result

def structural_surface(root,project_paths,motorola_paths,projections,empty_output,deadline):
    root=Path(root);require(root.is_absolute() and root.resolve(strict=True)==root,'canonical whole view root required')
    require(type(project_paths) is set and type(motorola_paths) is set and not project_paths.intersection(motorola_paths),'distinct measured Git/non-Git namespaces required')
    destinations={r['destination']:r for r in projections};leaves=project_paths|motorola_paths|set(destinations)|{'.repo','out'};dirs=parents(leaves)
    unknown=[];observed=[];pending=[(root,'')];seen_dirs=[]
    while pending:
        budget(deadline);directory,local=pending.pop();old=directory.lstat();seen_dirs.append((directory,identity(old)));fd=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            require(identity(os.fstat(fd))==identity(old),'structural source directory FD moved')
            with os.scandir(fd) as scan:
                for entry in scan:
                    budget(deadline);name=entry.name;relative=(local+'/' if local else '')+name;s=os.stat(name,dir_fd=fd,follow_symlinks=False);row=dict(path=relative,identity=list(identity(s)))
                    if relative in project_paths|motorola_paths:
                        require(stat.S_ISDIR(s.st_mode),'measured source project/blob tree replaced by alias/special');row['kind']='measured_source_root'
                    elif relative in destinations:
                        declaration=destinations[relative]
                        require((declaration['kind']=='linkfile' and stat.S_ISLNK(s.st_mode)) or (declaration['kind']=='copyfile' and stat.S_ISREG(s.st_mode)),'declared source projection type differs')
                        row['kind']='declared_source_projection'
                        if stat.S_ISLNK(s.st_mode):row['target']=os.readlink(name,dir_fd=fd)
                    elif relative=='.repo':
                        require(stat.S_ISDIR(s.st_mode),'explicit repo metadata boundary is not ordinary');row['kind']='explicit_non_source_repo_metadata_boundary'
                    elif relative=='out':
                        require(stat.S_ISDIR(s.st_mode) and os.path.samefile(root/'out',empty_output),'exact new empty output boundary required')
                        child=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                        try:require(not os.listdir(child),'source collection output boundary is not empty')
                        finally:os.close(child)
                        row['kind']='explicit_empty_non_source_build_output_boundary'
                    elif relative in dirs:
                        require(stat.S_ISDIR(s.st_mode),'structural source parent replaced by alias/special');row['kind']='source_structural_directory';pending.append((directory/name,relative))
                    else:
                        row['kind']='unknown_source_namespace';unknown.append(dict(path=relative,kind='unmodeled_source_namespace',actual_diagnostic=unknown_tree(directory/name,deadline)))
                        if stat.S_ISLNK(s.st_mode):row['target']=os.readlink(name,dir_fd=fd)
                        # The bounded actual contents remain diagnostic only.
                        # Any unknown entry holds the whole-source gate.
                    observed.append(row);require(len(observed)<=200000,'bounded structural source surface')
            require(identity(os.fstat(fd))==identity(old) and identity(directory.lstat())==identity(old),'structural source namespace moved')
        finally:os.close(fd)
    for directory,expected in seen_dirs:
        budget(deadline);require(identity(directory.lstat())==expected,'structural source directory changed after earlier traversal')
    names={r['path'] for r in observed};require(leaves<=names,'whole declared source root/projection/boundary missing')
    result=dict(schema='org.trillionnium.audit.actual-source-structural-surface.v1',root=str(root),root_identity=list(identity(root.lstat())),entries=sorted(observed,key=lambda r:r['path']),unknown_entries=sorted(unknown,key=lambda r:r['path']),complete=True,accepted=not unknown,repo_metadata_not_claimed_as_source_contents=True,output_boundary_empty=True,observations_sequential_not_globally_atomic=True,source_bom_qualified=False)
    budget(deadline);return result
