"""Actual local Git/FD tests and synthetic whole-graph mechanism negatives.

The 1170 graph fixture contains generated Git object bytes, not ROG measures.
Only ActualCollectorTests create and read real local Git checkouts/blob trees.
"""
import base64,copy,hashlib,importlib.util,io,json,os,posixpath,subprocess,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from unittest import mock
TOOLS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(TOOLS))
import owner_source_provenance as m
CONTROL_FIXTURE_FILES=1594

def inventory(files):
    rows=[dict(path=p,git_mode=mode,git_blob=m.git_oid('blob',raw),bytes=len(raw),sha256=m.sha(raw),symlink_target=raw.decode() if mode=='120000' else None,lfs=None) for p,raw,mode in files]
    tree=m.tree_oid(rows);commit=('tree '+tree+'\nauthor Fixture <fixture@local.invalid> 1 +0000\ncommitter Fixture <fixture@local.invalid> 1 +0000\n\nmechanism only\n').encode();head=m.git_oid('commit',commit)
    raw=b''.join((r['git_mode']+' blob '+r['git_blob']+'\t'+r['path']).encode()+b'\0' for r in rows)
    return dict(schema=m.INVENTORY_SCHEMA,root='/unexecuted/mechanism',head=head,tree=tree,raw_commit_base64=base64.b64encode(commit).decode(),raw_ls_tree_base64=base64.b64encode(raw).decode(),status_query=['status','--porcelain=v1','-z','--untracked-files=all','--ignored=matching'],raw_status_before_base64='',raw_status_after_base64='',head_after=head,tree_after=tree,source_files=rows,gitlinks=[],source_bytes=sum(r['bytes'] for r in rows),complete=True,external_git_filters_disabled=True,index_matches_committed_tree=True,uncommitted_attributes_empty=True)

def fixture_source_root():
    root=TOOLS.parent
    if not all((root/path).is_file() for path in (m.SOURCE_CHECKER,m.SDK_CHECKER)):
        value=os.environ.get('OWNER_BOM_FIXTURE_SOURCE_ROOT')
        m.require(type(value) is str and Path(value).is_absolute(),'explicit staging checker fixture root required')
        root=Path(value)
    for name,digest in ((m.SOURCE_CHECKER,m.SOURCE_CHECKER_SHA),(m.SDK_CHECKER,m.SDK_CHECKER_SHA)):
        m.require(m.sha(m.read_stable(root/name,1024*1024,time.monotonic()+10))==digest,'fixture checker byte/hash differs from source profile')
    return root

def graph_fixture(control_count=CONTROL_FIXTURE_FILES):
    actual_root=fixture_source_root()
    control_files=[(m.SOURCE_CHECKER,(actual_root/m.SOURCE_CHECKER).read_bytes(),'100644'),(m.SDK_CHECKER,(actual_root/m.SDK_CHECKER).read_bytes(),'100644'),('android-integration/working-tree/vendor/trillionnium/owner.txt',b'owner source','100644')]
    control_files += [('source/f'+str(i),b'ordinary','100644') for i in range(control_count-len(control_files))]
    control=inventory(control_files);ordinary=inventory([('owner.txt',b'owner source','100644')])
    candidate=dict(commit=control['head'],tree=control['tree'],archive_sha256='a'*64,control_regular_files=control_count)
    projection_projects=sorted({r['project'] for r in m.MANIFEST_PROJECTIONS})
    fixed_projects=set(projection_projects)|m.PRIVATE_PROJECT_PATHS
    invs={'p'+str(i).zfill(4):copy.deepcopy(ordinary) for i in range(m.MANIFEST_COUNT-1-len(fixed_projects))};invs.update({p:copy.deepcopy(ordinary) for p in fixed_projects});invs['trillionnium-os']=control
    for project in projection_projects:
        sources={r['source'] for r in m.MANIFEST_PROJECTIONS if r['project']==project}
        invs[project]=inventory([(source+'/ordinary.txt' if project=='build/make' and source in ('core','target','tools') else source,b'projection source: '+source.encode(),'100644') for source in sorted(sources)])
    def project_xml(project,inv):
        projections=''.join('<'+r['kind']+' src="'+r['source']+'" dest="'+r['destination']+'"/>' for r in m.MANIFEST_PROJECTIONS if r['project']==project)
        return ('<project name="fixture/'+project+'" path="'+project+'" revision="'+inv['head']+'">'+projections+'</project>').encode()
    manifest=b'<manifest>'+b''.join(project_xml(p,inv) for p,inv in invs.items())+b'</manifest>'
    private=sorted(m.PRIVATE_PROJECT_PATHS)
    rows=[dict(path=p,head=inv['head'],tree=inv['tree'],query_resolved=True,raw_git_status_base64='',git_status_bytes=0,git_status_sha256=m.sha(b'')) for p,inv in invs.items() if p not in set(private)|{'trillionnium-os'}]
    vector=dict(schema=m.VECTOR_SCHEMA,source_commit=candidate['commit'],source_tree=candidate['tree'],source_archive_sha256=candidate['archive_sha256'],resolved_manifest_sha256=m.sha(manifest),projects=rows,complete=True)
    manifest_inv=inventory([('trillionnium-fogos.xml',manifest,'100644')])
    entries=[dict(path='proprietary.bin',kind='regular',bytes=4,sha256=m.sha(b'blob'),mode=0o644)]
    blobs=[dict(schema='org.trillionnium.owner-non-git-content-tree.v1',path=p,entries=copy.deepcopy(entries),before_inventory_sha256=m.sha(m.canonical(entries)),after_inventory_sha256=m.sha(m.canonical(entries)),complete=True) for p in sorted(m.MOTOROLA_PATHS)]
    common=dict(source_commit=candidate['commit'],source_tree=candidate['tree'],source_archive_sha256=candidate['archive_sha256'],complete=True)
    generated=dict(common,schema='org.trillionnium.owner-generated-source-delta.v1',entries=[],unavailable_paths=[],source_content_inventory_complete=True)
    raw=m.canonical(dict(ok=True,errors=[],facts=dict(claim_ceiling='ANDROID_OWNER_OPEN_SOURCE_CLOSURE_PASSED_NOT_COMPILED',automatic_effect_redispatch=False,soong_compiled=False,selinux_compiled=False,target_files_built=False,image_included=False,physical_device_observed=False,public_release=False,sdk_selection=dict(owner_old_static_and_feature_edges_absent=True,owner_bool_unconditional_restricted_product_statement_verified=True))))
    source_inputs=[dict(project='trillionnium-os',path=r['path'],sha256=r['sha256'],git_blob=r['git_blob']) for r in control['source_files'][:4]]
    selection=dict(common,schema='org.trillionnium.owner-semantic-source-selection.v1',scope='source_only_not_compiled_or_installed',measured_source_graph=True,selected_role_counts={'codex':1,'owner_host':1,'owner_core':1,'provider_adapter':1},legacy_role_counts={r:0 for r in m.LEGACY_ROLES},source_inputs=source_inputs,checker_returncode=0,checker_stdout_base64=base64.b64encode(raw).decode(),checker_stdout_sha256=m.sha(raw),actual_overlay_files=1)
    archive=dict(all_archive_bytes_match_measured_git_tree=True,sha256=candidate['archive_sha256'],regular_files=control_count)
    custody=dict(schema='org.trillionnium.audit.frozen-candidate-custody.v1',source_commit=candidate['commit'],source_tree=candidate['tree'],tracked_files_verified=control_count,every_archive_file_matches_tested_frozen_git_blob=True,source_archive=dict(bytes=1,sha256=candidate['archive_sha256']))
    observations=[]
    for declaration in m.MANIFEST_PROJECTIONS:
        _,target=m.projected_source_rows(declaration,invs);digest=m.sha(m.canonical(target));kind=declaration['kind']
        observations.append(dict(declaration,observed_kind='symlink' if kind=='linkfile' else 'regular',symlink_target=posixpath.relpath(declaration['project']+'/'+declaration['source'],posixpath.dirname(declaration['destination']) or '.') if kind=='linkfile' else None,actual_target_files=target,target_file_inventory_complete=True,before_target_inventory_sha256=digest,after_target_inventory_sha256=digest))
    view='/unexecuted/mechanism/view';generations={p:dict(physical_work_tree=view+'/'+p,raw_before_base64=base64.b64encode((invs[p]['head']+'\n'+invs[p]['tree']+'\n').encode()).decode(),raw_after_base64=base64.b64encode((invs[p]['head']+'\n'+invs[p]['tree']+'\n').encode()).decode()) for p in projection_projects}
    projections=dict(common,schema='org.trillionnium.owner-manifest-projection-observations.v1',resolved_manifest_sha256=m.sha(manifest),physical_view_root=view,project_git_observations=generations,projections=observations)
    composition=dict(common,schema='org.trillionnium.audit.actual-exact-private-android-source-binding.v1',actual_refreshed13_composition_candidate_bound=True,private_project_count=m.PRIVATE_COUNT,private1170_static_manifest_sha256=m.sha(manifest),manifest_head=manifest_inv['head'],manifest_tree=manifest_inv['tree'],private_projects=[dict(path=p,private_repository='/unexecuted/mechanism/private/'+p,private_head=invs[p]['head'],private_tree=invs[p]['tree']) for p in private],source_bom_qualified=False,independent_migration_approval_asserted=False,canonical_source_authority_modified=False,installed=False,release_qualified=False)
    return [candidate,manifest,invs,copy.deepcopy(vector),copy.deepcopy(vector),private,manifest_inv,blobs,generated,selection,archive,custody,projections,composition]

class ActualCollectorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'repo';self.root.mkdir();self.env=dict(os.environ,GIT_AUTHOR_NAME='Local Fixture',GIT_AUTHOR_EMAIL='fixture@local.invalid',GIT_COMMITTER_NAME='Local Fixture',GIT_COMMITTER_EMAIL='fixture@local.invalid')
        self.git('init','-q');(self.root/'a').write_bytes(b'real tracked bytes');(self.root/'dir').mkdir();(self.root/'dir/b').write_bytes(b'executable');(self.root/'dir/b').chmod(0o755);(self.root/'dir.name').write_bytes(b'directory sorting');(self.root/'alias').symlink_to('a');(self.root/'.gitignore').write_text('generated.tmp\n');self.git('add','.');self.git('-c','commit.gpgsign=false','commit','-qm','fixture')
        self.head=self.git('rev-parse','HEAD').decode().strip();self.tree=self.git('rev-parse','HEAD^{tree}').decode().strip()
    def tearDown(self):self.temp.cleanup()
    def git(self,*args):
        result=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-C',str(self.root),*args],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20);self.assertEqual(result.returncode,0,result.stderr);return result.stdout
    def collect(self):return m.collect_git_checkout(self.root,self.head,self.tree,time.monotonic()+10)
    def test_real_git_bytes_tree_and_symlink(self):
        value=self.collect();self.assertEqual(m.tree_oid(value['source_files']),self.tree);self.assertEqual(next(x for x in value['source_files'] if x['path']=='alias')['symlink_target'],'a');self.assertFalse(value['independent_approval_asserted'])
    def test_real_dirty_rejected(self):
        (self.root/'a').write_bytes(b'changed');self.assertRaises(m.SourceError,self.collect)
    def test_real_ignored_generated_rejected(self):
        (self.root/'generated.tmp').write_text('not waived');self.assertRaises(m.SourceError,self.collect)
    def test_actual_wrong_head_rejected(self):self.assertRaises(m.SourceError,m.collect_git_checkout,self.root,'0'*40,self.tree,time.monotonic()+10)
    def test_actual_git_failure_keeps_project_returncode_and_stderr_digest(self):
        (self.root/'.git/config').write_bytes(b'[core\n')
        expected=subprocess.run(['/usr/bin/git','-C',str(self.root),'config','--local','--name-only','--get-regexp',r'^filter\.'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(expected.returncode,0)
        with self.assertRaises(m.SourceError) as caught:
            m.collect_git_checkout(self.root,self.head,self.tree,time.monotonic()+10,'packages/modules/Nfc')
        message=str(caught.exception)
        self.assertIn("project='packages/modules/Nfc'",message);self.assertIn('actual_rc='+str(expected.returncode),message)
        self.assertIn('stderr_bytes='+str(len(expected.stderr)),message);self.assertIn('stderr_sha256='+m.sha(expected.stderr),message)
        self.assertIn(repr(expected.stderr[:512])[2:-1],message)
    def test_real_symlink_input_rejected(self):self.assertRaises(m.SourceError,m.measure_regular,self.root/'alias',100,time.monotonic()+1)
    def test_actual_read_bound_rejected(self):self.assertRaises(m.SourceError,m.measure_regular,self.root/'a',1,time.monotonic()+1)
    def test_fd_hash_late_completion_rejected(self):
        original=m.hashlib.sha256
        class Delayed:
            def __init__(self):self.h=original()
            def update(self,b):self.h.update(b)
            def hexdigest(self):value=self.h.hexdigest();time.sleep(.04);return value
        with mock.patch.object(m.hashlib,'sha256',side_effect=Delayed):self.assertRaises(TimeoutError,m.measure_regular,self.root/'a',100,time.monotonic()+.02)
    def test_real_non_git_two_pass_and_mode(self):
        root=Path(self.temp.name)/'blob';root.mkdir();root.chmod(0o755);(root/'empty').mkdir();(root/'empty').chmod(0o755);(root/'proprietary.bin').write_bytes(b'blob');(root/'proprietary.bin').chmod(0o644);value=m.collect_blob_tree(root,'vendor/motorola/fogos',time.monotonic()+2);self.assertEqual(len(value['entries']),2);self.assertEqual(value['before_inventory_sha256'],value['after_inventory_sha256'])
    def test_real_non_git_special_link_rejected(self):
        root=Path(self.temp.name)/'blob';root.mkdir();root.chmod(0o755);(root/'alias').symlink_to(self.root/'a');self.assertRaises(m.SourceError,m.collect_blob_tree,root,'vendor/motorola/fogos',time.monotonic()+2)
    def test_real_non_git_group_write_rejected(self):
        root=Path(self.temp.name)/'blob';root.mkdir();root.chmod(0o755);(root/'x').write_bytes(b'blob');(root/'x').chmod(0o664);self.assertRaises(m.SourceError,m.collect_blob_tree,root,'vendor/motorola/fogos',time.monotonic()+2)

class GraphMechanismTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture=graph_fixture()
    def value(self):return copy.deepcopy(self.fixture)
    def test_mechanism_complete1170_positive_not_release(self):
        value=m.validate_graph(*self.value());self.assertEqual(value['decision'],'PASS_MEASURED_OWNER_GRAPH');self.assertFalse(value['production_ready']);self.assertFalse(value['clean_public_source_claim'])
    def test_v3_exact16_includes_nfc_and_original1153(self):
        graph=self.value();value=m.validate_graph(*graph)
        self.assertEqual(m.PRIVATE_COUNT,16);self.assertEqual(m.ORIGINAL_COUNT,1153)
        self.assertEqual(set(value['private_project_paths']),m.PRIVATE_PROJECT_PATHS)
        self.assertIn('packages/modules/Nfc',value['private_project_paths'])
        self.assertEqual(len(graph[3]['projects']),1153)
    def test_old_private15_not_accepted_by_v3(self):
        self.reject(lambda v:v[5].remove('packages/modules/Nfc'))
    def test_sixteenth_unrelated_private_project_not_substitute_for_nfc(self):
        def wrong(v):v[5][v[5].index('packages/modules/Nfc')]='p0000'
        self.reject(wrong)
    def test_old_v2_profile_or_input_schema_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'input.json'
            for schema,profile in ((m.INPUT_SCHEMA,'owner-open-whole-control-v2'),('org.trillionnium.owner-source-provenance-input.v2',m.PROFILE)):
                with self.subTest(schema=schema,profile=profile):
                    path.write_bytes(m.canonical(dict(schema=schema,profile_id=profile,candidate={},documents={},private_project_paths=[])))
                    with self.assertRaisesRegex(m.SourceError,'wrong owner profile/schema'):m.inspect_packet(path,time.monotonic()+1)
    def test_new_control_tree_exact1595_supported_without_count_waiver(self):
        value=m.validate_graph(*graph_fixture(1595));self.assertEqual(value['control_regular_files'],1595)
    def test_wrong_explicit_control_count_not_inferred_or_waived(self):self.reject(lambda v:v[0].update(control_regular_files=1595))
    def test_wrong_custody_source_count_is_held(self):self.reject(lambda v:v[11].update(tracked_files_verified=1595))
    def test_private_composition_old_lower_generation_is_held(self):self.reject(lambda v:v[13]['private_projects'][-1].update(private_head='0'*40))
    def test_private_manifest_composition_generation_is_held(self):self.reject(lambda v:v[13].update(manifest_head='0'*40))
    def test_projection_physical_git_observation_generation_is_held(self):self.reject(lambda v:v[12]['project_git_observations']['build/make'].update(raw_after_base64=base64.b64encode(b'0'*40+b'\n'+b'0'*40+b'\n').decode()))
    def reject(self,mutate):
        value=self.value();mutate(value);self.assertRaises((m.SourceError,KeyError),m.validate_graph,*value)
    def test_missing_inventory(self):self.reject(lambda v:v[2].pop('p0999'))
    def test_incomplete_inventory(self):self.reject(lambda v:v[2]['p0999'].update(complete=False))
    def test_raw_dirty_not_overridden_by_boolean(self):self.reject(lambda v:v[3]['projects'][0].update(raw_git_status_base64=base64.b64encode(b'!! x\0').decode(),clean_git_status_observed=True))
    def test_unknown_query_rejected(self):self.reject(lambda v:v[4]['projects'][0].update(query_resolved=False))
    def test_after_tree_changed(self):self.reject(lambda v:v[4]['projects'][0].update(tree='0'*40))
    def test_before_manifest_splice(self):self.reject(lambda v:v[3].update(resolved_manifest_sha256='0'*64))
    def test_wrong_candidate_tuple(self):self.reject(lambda v:v[4].update(source_commit='0'*40))
    def test_generated_source_not_waived(self):self.reject(lambda v:v[8].update(entries=[dict(path='generated.bp',sha256='a'*64)]))
    def test_missing_motorola(self):self.reject(lambda v:v[7].pop())
    def test_changed_motorola(self):self.reject(lambda v:v[7][0].update(after_inventory_sha256='0'*64))
    def test_legacy_selection_rejected(self):self.reject(lambda v:v[9]['legacy_role_counts'].update(ai_authority=1))
    def test_multiple_codex_rejected(self):self.reject(lambda v:v[9]['selected_role_counts'].update(codex=2))
    def test_checker_nonzero_actual_rc_rejected(self):self.reject(lambda v:v[9].update(checker_returncode=7))
    def test_checker_stdout_moved(self):self.reject(lambda v:v[9].update(checker_stdout_sha256='0'*64))
    def test_overlay_not_in_actual_private_tree(self):self.reject(lambda v:v[2]['vendor/trillionnium'].update(source_files=[]))
    def test_manifest_git_source_splice(self):self.reject(lambda v:v[6].update(source_files=[]))
    def test_forged_raw_commit_rejected(self):self.reject(lambda v:v[2]['p0999'].update(raw_commit_base64=base64.b64encode(b'tree '+b'0'*40+b'\n').decode()))
    def test_missing_tracked_file_rejected(self):self.reject(lambda v:v[2]['trillionnium-os']['source_files'].pop())
    def test_unknown_source_symlink_target(self):
        inv=inventory([('alias',b'../../outside','120000')]);self.assertRaises(m.SourceError,m.source_link_closure,{'p':inv})
    def test_source_symlink_cycle(self):
        inv=inventory([('a',b'b','120000'),('b',b'a','120000')]);self.assertRaises(m.SourceError,m.source_link_closure,{'p':inv})
    def test_json_duplicate_and_nonfinite(self):
        for raw in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.subTest(raw=raw):self.assertRaises(m.SourceError,m.parse,raw)
    def test_packet_wrong_profile_fails_before_missing_documents(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'input.json';path.write_bytes(m.canonical(dict(schema=m.INPUT_SCHEMA,profile_id='old-p0',candidate={},documents={},private_project_paths=[])));self.assertRaises(m.SourceError,m.inspect_packet,path,time.monotonic()+1)

if __name__=='__main__':unittest.main()
