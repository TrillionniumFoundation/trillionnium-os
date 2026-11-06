"""Synthetic full-graph ASB evidence, never actual Android observations.

The fixture catalog has genuine internally consistent Git objects for its
generated bodies. Its expected catalog SHA is an explicit in-memory test pin.
Production source bytes and production pins remain unchanged. Only synthetic
remote descriptor transport is mapped to bounded ordinary local fixture files;
all nested production validators execute, and actual FD tests stay separate.
"""
import base64, copy, difflib, hashlib, json, pathlib, tempfile, time
import owner_asb_fork_catalog as c

_retained=[]

def inventory(p, files, root, parent=None):
    rows=sorted(files,key=lambda x:x['path'].encode());tree=p.tree_oid(rows)
    raw=('tree '+tree+'\n'+('parent '+parent+'\n' if parent else '')+
         'author Fixture <fixture@local.invalid> 1 +0000\ncommitter Fixture <fixture@local.invalid> 1 +0000\n\nSynthetic complete source objects\n').encode()
    head=p.git_oid('commit',raw)
    ls=b''.join((r['git_mode']+' blob '+r['git_blob']+'\t'+r['path']).encode()+b'\0' for r in rows)
    return dict(schema=p.INVENTORY_SCHEMA,root=root,head=head,tree=tree,
        raw_commit_base64=base64.b64encode(raw).decode(),raw_ls_tree_base64=base64.b64encode(ls).decode(),
        source_files=rows,gitlinks=[],source_bytes=sum(r['bytes'] for r in rows),
        raw_status_before_base64='',raw_status_after_base64='',head_after=head,tree_after=tree,
        status_query=['status','--porcelain=v1','-z','--untracked-files=all','--ignored=matching'],
        complete=True,external_git_filters_disabled=True,index_matches_committed_tree=True,uncommitted_attributes_empty=True)

def file_row(p,name,raw,mode='100644'):
    return dict(path=name,git_mode=mode,git_blob=p.git_oid('blob',raw),bytes=len(raw),
                sha256=p.sha(raw),symlink_target=raw.decode() if mode=='120000' else None,lfs=None)

def synthetic_catalog(source,p):
    catalog=copy.deepcopy(json.loads((source/c.CATALOG_PATH).read_bytes()))
    bodies={};originals={};clones={};afters={}
    for spec in catalog['projects']:
        before=[];after=[]
        for f in spec['files']:
            a=('synthetic before '+spec['path']+'/'+f['path']+'\n').encode()
            b=('synthetic after '+spec['path']+'/'+f['path']+'\n').encode()
            patch=''.join(difflib.unified_diff(a.decode().splitlines(keepends=True),b.decode().splitlines(keepends=True),fromfile=f['patch']['old_label'],tofile=f['patch']['new_label'])).encode()
            for label,raw in [('before',a),('after',b)]:f[label]=dict(bytes=len(raw),sha256=p.sha(raw),git_blob_sha1=p.git_oid('blob',raw))
            f['patch'].update(bytes=len(patch),sha256=p.sha(patch));bodies[f['patch']['canonical_path']]=patch
            before.append(file_row(p,f['path'],a,f['git_mode']));after.append(file_row(p,f['path'],b,f['git_mode']))
        for name,raw,mode in [('fixture-ordinary',b'unchanged\n','100644'),('fixture-executable',b'#!/bin/sh\n','100755'),('fixture-link',b'fixture-ordinary','120000')]:
            row=file_row(p,name,raw,mode);before.append(row);after.append(copy.deepcopy(row))
        original=inventory(p,before,'/synthetic/original/'+spec['path'])
        clone=copy.deepcopy(original);clone['root']='/synthetic/private/'+spec['path']
        final=inventory(p,after,clone['root'],clone['head'])
        spec['historical_source_head']=original['head'];spec['historical_source_tree']=original['tree']
        originals[spec['path']]=original;clones[spec['path']]=clone;afters[spec['path']]=final
    for row in catalog['scoped_evidence']:
        raw=b'{"synthetic_fixture_only":true}\n';row.update(bytes=len(raw),sha256=p.sha(raw));bodies[row['canonical_path']]=raw
    c.validate_catalog(catalog);bodies[c.CATALOG_PATH]=c.canonical(catalog)
    return catalog,bodies,originals,clones,afters

def upgrade_graph_fixture(graph,p,source):
    catalog,bodies,originals,clones,afters=synthetic_catalog(source,p)
    temp=tempfile.TemporaryDirectory(prefix='owner-asb38-graph-');_retained.append(temp);local=pathlib.Path(temp.name);local.chmod(0o700)
    controls=[r for r in graph[2]['trillionnium-os']['source_files'] if not r['path'].startswith('source/f')]
    controls.extend(file_row(p,name,raw) for name,raw in sorted(bodies.items()))
    count=graph[0]['control_regular_files'];controls.extend(file_row(p,'source/f'+str(i),b'ordinary') for i in range(count-len(controls)))
    control=inventory(p,controls,'/synthetic/control')
    candidate=dict(graph[0],commit=control['head'],tree=control['tree']);stage='/var/lib/codex-trillionnium-private-source-'+candidate['commit'][:7]+'-20261003-r1'
    common=dict(source_commit=candidate['commit'],source_tree=candidate['tree'],source_archive_sha256=candidate['archive_sha256'])
    graph[0]=candidate;graph[2]['trillionnium-os']=control
    transport={};counter=0
    def publish(logical,value,raw=None):
        nonlocal counter
        raw=p.canonical(value) if raw is None else raw
        actual=local/(str(counter).zfill(4)+'.raw');counter+=1;actual.write_bytes(raw);actual.chmod(0o600)
        desc=dict(path=logical,bytes=len(raw),sha256=p.sha(raw));transport[logical]=(desc,actual)
        return desc
    projects=[];source4={};maps={}
    for spec in catalog['projects']:
        name=spec['path'];root=stage+('/security-forks/' if spec['baseline_kind']=='previous_complete_private' else '/synthetic-original/')+name
        private=stage+'/asb-forks/'+name
        original=copy.deepcopy(originals[name]);original['root']=root
        clone=copy.deepcopy(clones[name]);clone['root']=private
        final=copy.deepcopy(afters[name]);final['root']=private;graph[2][name]=final
        row=dict(path=name,private_repository=private,private_head=final['head'],private_tree=final['tree'],exact_changed_paths=[f['path'] for f in spec['files']],complete=True,complete_git_objects=dict(files=1,bytes=1,no_hardlinks_or_alternates=True),original_git_pointer_before=dict(synthetic=True),original_git_pointer_after=dict(synthetic=True))
        for label,inv in [('original_before',original),('original_after',original),('clone_before',clone),('clone_after',final)]:row[label]=publish(stage+'/fixture/'+name.replace('/','_')+'-'+label+'.json',inv)
        for label,inv in [('original_surface_before',original),('original_surface_after',original),('clone_surface_before',clone),('clone_surface_after',final)]:
            surface=dict(schema='org.trillionnium.audit.actual-project-source-surface.v2',root=inv['root'],head=inv['head'],tree=inv['tree'],tracked_files=len(inv['source_files']),complete=True,accepted=True,unknown_entries=[],unknown_content_diagnostics=[],before_namespace_sha256='d'*64,after_namespace_sha256='d'*64,source_bom_qualified=False)
            row[label]=publish(stage+'/fixture/'+name.replace('/','_')+'-'+label+'.json',surface)
        meta=dict(root=root+'/.git',root_fd9=[1]*9,files={},complete=True)
        row.update(original_metadata_before=meta,original_metadata_after=copy.deepcopy(meta));maps['baseline:'+name]=meta;projects.append(row)
        if spec['baseline_kind']=='previous_complete_private':source4[name]=dict(path=name,private_repository=root,private_head=original['head'],private_tree=original['tree'],complete=True)
    for name in c.PRIOR_PRIVATE_PROJECTS:
        if name not in source4:
            inv=graph[2][name];source4[name]=dict(path=name,private_repository=stage+'/projects/'+name,private_head=inv['head'],private_tree=inv['tree'],private_clean_status_verified=True,complete=True)
        maps['prior:'+name]=dict(root=source4[name]['private_repository']+'/.git',root_fd9=[1]*9,files={},complete=True)
    for name in ('control','manifest'):maps[name]=dict(root=stage+'/'+name+'/.git',root_fd9=[1]*9,files={},complete=True)
    source13=dict(common,schema='org.trillionnium.audit.actual-next-candidate-private13-source-composition.v1',projects=[source4[n] for n in sorted(c.PRIOR_PRIVATE_PROJECTS-{'external/libopenapv','frameworks/base','packages/modules/Nfc'})],complete=True,source_bom_qualified=False,original_source_or_git_writes_performed=False,installed=False,production_ready=False)
    defensive=dict(source13,schema='org.trillionnium.audit.actual-complete-defensive-private-forks.v1',projects=[source4[n] for n in sorted({'external/libopenapv','frameworks/base','packages/modules/Nfc'})])
    receipt=dict(common,schema=c.RECEIPT_SCHEMA,complete=True,completed_project_count=24,actual_error=None,original_source_or_metadata_written=False,full_ASB_coverage_qualified=False,source_bom_qualified=False,compiled=False,installed=False,production_ready=False,all_original_and_retained_metadata_before=maps,all_original_and_retained_metadata_after=copy.deepcopy(maps),projects=projects,attempt=1,stage=stage)
    catalograw=bodies[c.CATALOG_PATH];receipt['catalog_descriptor']=publish(stage+'/control/'+c.CATALOG_PATH,None,catalograw);receipt['catalog_sha256']=p.sha(catalograw)
    receipt['source4_composition_descriptor']=publish(stage+'/fixture/source13.json',source13);receipt['source4_defensive_descriptor']=publish(stage+'/fixture/defensive3.json',defensive)
    receipt['scoped_evidence_descriptors']=[publish(stage+'/control/'+e['canonical_path'],None,bodies[e['canonical_path']]) for e in catalog['scoped_evidence']]
    import xml.etree.ElementTree as ET
    # Preserve every declaration and rebind only each actual synthetic HEAD.
    tree=ET.fromstring(graph[1])
    for node in tree.findall('project'):node.attrib['revision']=graph[2][node.attrib['path']]['head']
    graph[1]=ET.tostring(tree)
    graph[6]=inventory(p,[file_row(p,'trillionnium-fogos.xml',graph[1])],'/synthetic/manifest')
    for index in (3,4):
        graph[index].update(common,resolved_manifest_sha256=p.sha(graph[1]))
    for index in (8,9,12,13):graph[index].update(common)
    graph[11].update(source_commit=candidate['commit'],source_tree=candidate['tree'])
    graph[12]['resolved_manifest_sha256']=p.sha(graph[1])
    graph[13].update(schema='org.trillionnium.audit.actual-exact-private-android-source-binding.v2',actual_asb24_fullfork_candidate_bound=True,private1170_static_manifest_sha256=p.sha(graph[1]),manifest_head=graph[6]['head'],manifest_tree=graph[6]['tree'],asb24_fullfork_receipt=publish(stage+'/fixture/complete24.json',receipt))
    graph[13]['private_projects']=[dict(path=name,private_repository=stage+'/asb-forks/'+name if name in c.AFFECTED_PROJECTS else source4[name]['private_repository'],private_head=graph[2][name]['head'],private_tree=graph[2][name]['tree']) for name in sorted(c.PRIVATE_PROJECTS)]
    # Explicit test double for descriptor transport, not validator substitution.
    if not hasattr(p,'_asb38_fixture_original_reader'):p._asb38_fixture_original_reader=p.read_descriptor;p._asb38_fixture_transports={}
    p._asb38_fixture_transports.update(transport)
    def read(desc,deadline,maximum=128*1024*1024):
        entry=p._asb38_fixture_transports.get(desc['path'])
        if entry is None:return p._asb38_fixture_original_reader(desc,deadline,maximum)
        expected,actual=entry;p.require(desc==expected,'synthetic evidence descriptor changed')
        actualraw=actual.read_bytes();return p._asb38_fixture_original_reader(p.descriptor(actual,actualraw),deadline,maximum)
    p.read_descriptor=read;p.ASB_CATALOG_SHA=p.sha(catalograw)
    return graph


def rebind_graph_archive_sha(graph,p,digest):
    """Publish current synthetic archive identity through every real nested input."""
    graph[0]['archive_sha256']=digest
    for index in (3,4,8,9,12,13):graph[index]['source_archive_sha256']=digest
    graph[11]['source_archive']['sha256']=digest
    receipt_desc=graph[13]['asb24_fullfork_receipt']
    receipt=p.parse(p.read_descriptor(receipt_desc,time.monotonic()+10))
    def publish(desc,value):
        expected,actual=p._asb38_fixture_transports[desc['path']]
        if desc!=expected:raise ValueError('archive fixture descriptor changed')
        raw=p.canonical(value);actual.write_bytes(raw)
        new=dict(path=desc['path'],bytes=len(raw),sha256=p.sha(raw))
        p._asb38_fixture_transports[desc['path']]=(new,actual)
        return new
    for key in ('source4_composition_descriptor','source4_defensive_descriptor'):
        value=p.parse(p.read_descriptor(receipt[key],time.monotonic()+10))
        value['source_archive_sha256']=digest
        receipt[key]=publish(receipt[key],value)
    receipt['source_archive_sha256']=digest
    graph[13]['asb24_fullfork_receipt']=publish(receipt_desc,receipt)
