"""R2 real local Git/LFS/FD/projection tests and bounded index mechanisms.

Every physical checkout and projected destination belongs to a disposable
local fixture. No Android checkout, ROG image, filter or network is executed.
"""
import base64,copy,io,json,os,posixpath,subprocess,sys,tarfile,tempfile,time,unittest
from pathlib import Path
from unittest import mock
TOOLS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(TOOLS))
import owner_source_provenance as m
from test_owner_source_provenance import inventory,graph_fixture,fixture_source_root

def desc(path):return m.descriptor(path,path.read_bytes())

class RealLfsTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'repo';self.root.mkdir();self.env=dict(os.environ,GIT_AUTHOR_NAME='Fixture',GIT_AUTHOR_EMAIL='fixture@local.invalid',GIT_COMMITTER_NAME='Fixture',GIT_COMMITTER_EMAIL='fixture@local.invalid',GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null')
        self.git('init','-q');self.payload=b'PK\x03\x04'+bytes(range(256))*4096;self.pointer=('version https://git-lfs.github.com/spec/v1\noid sha256:'+m.sha(self.payload)+'\nsize '+str(len(self.payload))+'\n').encode()
        (self.root/'.gitattributes').write_bytes(b'*.bin filter=lfs -text\n');(self.root/'ordinary').write_bytes(b'ordinary source');(self.root/'webview.bin').write_bytes(self.pointer);self.commit();(self.root/'webview.bin').write_bytes(self.payload)
    def tearDown(self):self.temp.cleanup()
    def git(self,*args):
        result=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','filter.lfs.clean=','-c','filter.lfs.smudge=','-c','filter.lfs.process=','-c','filter.lfs.required=false','-C',str(self.root),*args],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(result.returncode,0,result.stderr);return result.stdout
    def commit(self):
        self.git('add','.');self.git('-c','commit.gpgsign=false','commit','-qm','fixture');self.head=self.git('rev-parse','HEAD').decode().strip();self.tree=self.git('rev-parse','HEAD^{tree}').decode().strip()
    def collect(self):return m.collect_git_checkout(self.root,self.head,self.tree,time.monotonic()+10)
    def test_actual_hydrated_bytes_pointer_committed_attribute_closed(self):
        value=self.collect();row=next(r for r in value['source_files'] if r['path']=='webview.bin');self.assertEqual(row['git_blob'],m.git_oid('blob',self.pointer));self.assertEqual(row['sha256'],m.sha(self.payload));self.assertEqual(row['bytes'],len(self.payload));self.assertEqual(base64.b64decode(value['raw_status_before_base64']),b' M webview.bin\0');m.validate_inventory(value)
    def test_external_filter_command_is_not_executed(self):
        marker=Path(self.temp.name)/'filter-executed';command='touch '+str(marker)
        for key in ('clean','smudge','process'):self.git('config','filter.lfs.'+key,command)
        self.git('config','filter.lfs.required','true');self.collect();self.assertFalse(marker.exists())
    def test_unhydrated_pointer_is_held(self):
        (self.root/'webview.bin').write_bytes(self.pointer);self.assertRaises(m.SourceError,self.collect)
    def test_actual_payload_wrong_bytes_is_held(self):
        (self.root/'webview.bin').write_bytes(b'x'+self.payload[1:]);self.assertRaises(m.SourceError,self.collect)
    def test_payload_wrong_size_is_held(self):
        (self.root/'webview.bin').write_bytes(self.payload[:-1]);self.assertRaises(m.SourceError,self.collect)
    def test_pointer_without_committed_lfs_attribute_is_held(self):
        (self.root/'webview.bin').write_bytes(self.pointer);(self.root/'.gitattributes').unlink();self.commit();(self.root/'webview.bin').write_bytes(self.payload);self.assertRaises(m.SourceError,self.collect)
    def test_uncommitted_attribute_override_is_held(self):
        (self.root/'.git/info/attributes').write_bytes(b'*.bin filter=lfs\n');self.assertRaises(m.SourceError,self.collect)
    def test_worktree_attribute_change_is_held(self):
        (self.root/'.gitattributes').write_bytes(b'*.bin filter=other\n');self.assertRaises(m.SourceError,self.collect)
    def test_index_must_equal_committed_full_tree(self):
        (self.root/'ordinary').write_bytes(b'index mismatch');self.git('add','ordinary');self.assertRaises(m.SourceError,self.collect)
    def test_lfs_does_not_waive_ordinary_dirty_source(self):
        (self.root/'ordinary').write_bytes(b'ordinary changed');self.assertRaises(m.SourceError,self.collect)
    def test_noncanonical_pointer_grammar_rejected(self):
        for raw in (self.pointer.replace(b'\n',b'\r\n'),self.pointer+b'ext-0 optional\n',self.pointer.replace(b'size ',b'size 0'),self.pointer.replace(b'sha256:',b'sha256:A')):
            with self.subTest(raw=raw[:100]):self.assertRaises(m.SourceError,m.parse_lfs_pointer,raw)
    def test_pointer_or_cached_attribute_proof_splice_rejected(self):
        value=self.collect();row=next(r for r in value['source_files'] if r['lfs']);row['lfs']['attributes_raw_base64']=base64.b64encode(b'other\0filter\0lfs\0').decode();self.assertRaises(m.SourceError,m.validate_inventory,value)

class RealProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.graph=graph_fixture()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.view=Path(self.temp.name)/'view';self.view.mkdir();self.files={}
        for declaration in m.MANIFEST_PROJECTIONS:
            project=declaration['project'];source=declaration['source'];directory,target=m.projected_source_rows(declaration,self.graph[2])
            for row in target:
                path=self.view/project/source
                if directory:path=path/row['path']
                path.parent.mkdir(parents=True,exist_ok=True);raw=b'projection source: '+source.encode();path.write_bytes(raw);path.chmod(0o644);self.files[path]=raw
            destination=self.view/declaration['destination'];destination.parent.mkdir(parents=True,exist_ok=True)
            if declaration['kind']=='linkfile':destination.symlink_to(posixpath.relpath(project+'/'+source,posixpath.dirname(declaration['destination']) or '.'))
            else:destination.write_bytes(self.files[self.view/project/source]);destination.chmod(0o644)
        for project in sorted({r['project'] for r in m.MANIFEST_PROJECTIONS}):
            root=self.view/project;inv=self.graph[2][project]
            def git(*args,input=None):
                result=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-C',str(root),*args],input=input,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(result.returncode,0,result.stderr);return result.stdout
            git('init','-q');git('add','-A');self.assertEqual(git('write-tree').decode().strip(),inv['tree']);self.assertEqual(git('hash-object','-w','-t','commit','--stdin',input=base64.b64decode(inv['raw_commit_base64'])).decode().strip(),inv['head']);git('update-ref','refs/heads/main',inv['head']);git('symbolic-ref','HEAD','refs/heads/main')
    def tearDown(self):self.temp.cleanup()
    def collect(self):return m.collect_manifest_projections(self.view,self.graph[1],self.graph[2],self.graph[0],time.monotonic()+10)
    def test_actual_all25_destinations_source_bytes_and_directory_closure(self):
        value=self.collect();self.assertEqual(len(value['projections']),25);self.assertFalse(value['source_bom_qualified']);m.validate_projections(value,self.graph[0],self.graph[1],self.graph[2])
    def test_missing_destination_is_held(self):
        (self.view/'build/envsetup.sh').unlink();self.assertRaises(FileNotFoundError,self.collect)
    def test_wrong_link_destination_is_held(self):
        path=self.view/'build/envsetup.sh';path.unlink();path.symlink_to('../buildspec.mk.default');self.assertRaises(m.SourceError,self.collect)
    def test_actual_copy_payload_difference_is_held(self):
        (self.view/'lk_inc.mk').write_bytes(b'wrong actual copy');self.assertRaises(m.SourceError,self.collect)
    def test_directory_projection_extra_untracked_file_is_held(self):
        (self.view/'build/make/core/extra.bp').write_bytes(b'untracked input');self.assertRaises(m.SourceError,self.collect)
    def test_directory_projection_missing_tracked_file_is_held(self):
        (self.view/'build/make/core/ordinary.txt').unlink();self.assertRaises(m.SourceError,self.collect)
    def test_directory_projection_untracked_empty_directory_is_held(self):
        (self.view/'build/make/core/extra').mkdir();self.assertRaises(m.SourceError,self.collect)
    def test_extra_manifest_missing_link_is_not_a_generated_waiver(self):
        raw=self.graph[1].replace(b'</project>',b'<linkfile src="owner.txt" dest="generated/required-input.bp"/></project>',1);self.assertRaises(m.SourceError,m.manifest_projections,raw)
    def test_projection_observation_missing_or_spliced_rejected(self):
        value=self.collect();value['projections'].pop();self.assertRaises(m.SourceError,m.validate_projections,value,self.graph[0],self.graph[1],self.graph[2])
    def test_old_lower_head_not_the_selected_private_generation_is_held(self):
        root=self.view/'build/make'
        # Make a real empty-tree commit while projected bytes remain intact.
        result=subprocess.run(['/usr/bin/git','-C',str(root),'hash-object','-w','-t','tree','--stdin'],input=b'',stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(result.returncode,0,result.stderr);tree=result.stdout.decode().strip();raw=('tree '+tree+'\nauthor Fixture <fixture@local.invalid> 1 +0000\ncommitter Fixture <fixture@local.invalid> 1 +0000\n\nold lower\n').encode();result=subprocess.run(['/usr/bin/git','-C',str(root),'hash-object','-w','-t','commit','--stdin'],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(result.returncode,0,result.stderr);head=result.stdout.decode().strip();result=subprocess.run(['/usr/bin/git','-C',str(root),'update-ref','refs/heads/main',head],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(result.returncode,0,result.stderr);self.assertRaises(m.SourceError,self.collect)

class RealDynamicControlTests(unittest.TestCase):
    def test_actual_two_commits_count_tree_archive_custody_growth(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)/'repo';root.mkdir();env=dict(os.environ,GIT_AUTHOR_NAME='Fixture',GIT_AUTHOR_EMAIL='fixture@local.invalid',GIT_COMMITTER_NAME='Fixture',GIT_COMMITTER_EMAIL='fixture@local.invalid')
            def git(*args):
                r=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','commit.gpgsign=false','-C',str(root),*args],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(r.returncode,0,r.stderr);return r.stdout
            git('init','-q');counts=[]
            for filename in ('ordinary','new-observer-tool'):
                (root/filename).write_bytes(filename.encode());git('add','.');git('commit','-qm',filename);head=git('rev-parse','HEAD').decode().strip();tree=git('rev-parse','HEAD^{tree}').decode().strip();inv=m.collect_git_checkout(root,head,tree,time.monotonic()+10);count=len(inv['source_files']);archive=git('archive','--format=tar.gz',head);digest=m.sha(archive);candidate=dict(commit=head,tree=tree,archive_sha256=digest,control_regular_files=count);custody=dict(schema='org.trillionnium.audit.frozen-candidate-custody.v1',source_commit=head,source_tree=tree,tracked_files_verified=count,every_archive_file_matches_tested_frozen_git_blob=True,source_archive=dict(bytes=len(archive),sha256=digest));m.validate_custody(custody,candidate);m.verify_control_archive(archive,inv,digest,count,time.monotonic()+10);counts.append(count)
                bad=copy.deepcopy(candidate);bad['control_regular_files']=count+1;self.assertRaises(m.SourceError,m.validate_custody,custody,bad);self.assertRaises(m.SourceError,m.verify_control_archive,archive,inv,digest,count+1,time.monotonic()+10)
            self.assertEqual(counts,[1,2])

class ShardedIndexTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.graph=graph_fixture()
    def setUp(self):self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700)
    def tearDown(self):self.temp.cleanup()
    def record(self,project,inv=None):
        directory=self.root/project.replace('/','_');directory.mkdir();directory.chmod(0o700);return m.publish_sharded_inventory(project,inv or inventory([('ordinary',b'actual metadata fixture','100644')]),directory,time.monotonic()+10)
    def store(self,records):
        graph=self.graph;entries=[dict(project=p,record=records.get(p,dict(path='/never-read/'+p,bytes=1,sha256='a'*64))) for p in graph[2]];index=dict(schema='org.trillionnium.owner-git-content-index.v1',profile_id=m.PROFILE,candidate=graph[0],resolved_manifest_sha256=m.sha(graph[1]),projects=entries);return m.InventoryStore(index,graph[0],graph[1],graph[5],time.monotonic()+10)
    def mutate_record(self,descriptor,mutate):
        path=Path(descriptor['path']);value=m.parse(path.read_bytes());mutate(value);path.write_bytes(m.canonical(value));return desc(path)
    def test_real_private_shards_raw_tree_reloaded_complete(self):
        inv=inventory([('source'+str(i),b'file'+str(i).encode(),'100644') for i in range(4100)]);record=self.record('p0999',inv);store=self.store({'p0999':record});self.assertEqual(store['p0999'],inv);self.assertEqual(store.file_count,4100);self.assertGreater(len(store.fixed),3);store.reverify()
    def test_new_inode_publication_refuses_existing_target(self):
        target=self.root/'same';target.write_bytes(b'original');self.assertRaises(FileExistsError,m._publish_new,self.root,'same',b'new',time.monotonic()+2);self.assertEqual(target.read_bytes(),b'original')
    def test_new_inode_publication_refuses_symlink_target(self):
        actual=self.root/'actual';actual.write_bytes(b'original');(self.root/'same').symlink_to(actual);self.assertRaises(FileExistsError,m._publish_new,self.root,'same',b'new',time.monotonic()+2);self.assertEqual(actual.read_bytes(),b'original')
    def test_publication_requires_private_parent(self):
        self.root.chmod(0o755);self.assertRaises(m.SourceError,m._publish_new,self.root,'new',b'x',time.monotonic()+2)
    def test_record_namespace_splice_is_held(self):
        record=self.record('p0999');record=self.mutate_record(record,lambda r:r.update(project='p0998'));store=self.store({'p0999':record});self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_missing_shard_is_held(self):
        record=self.record('p0999');record=self.mutate_record(record,lambda r:r.update(source_file_shards=[]));store=self.store({'p0999':record});self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_duplicate_shard_is_held(self):
        record=self.record('p0999');record=self.mutate_record(record,lambda r:r['source_file_shards'].append(copy.deepcopy(r['source_file_shards'][0])));store=self.store({'p0999':record});self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_wrong_count_is_held(self):
        record=self.record('p0999');record=self.mutate_record(record,lambda r:r.update(source_file_count=2));store=self.store({'p0999':record});self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_changed_raw_tree_descriptor_is_held(self):
        record=self.record('p0999');raw=m.parse(Path(record['path']).read_bytes());Path(raw['raw_ls_tree']['path']).write_bytes(b'changed');store=self.store({'p0999':record});self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_final_descriptor_recheck_rejects_changed_shard(self):
        record=self.record('p0999');store=self.store({'p0999':record});store['p0999'];raw=m.parse(Path(record['path']).read_bytes());Path(raw['source_file_shards'][0]['descriptor']['path']).write_bytes(b'changed');self.assertRaises(m.SourceError,store.reverify)
    def test_aggregate_file_bound_is_enforced(self):
        record=self.record('p0999');store=self.store({'p0999':record})
        with mock.patch.object(m,'MAX_GRAPH_FILES',0):self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_aggregate_metadata_bound_is_enforced(self):
        record=self.record('p0999');store=self.store({'p0999':record})
        with mock.patch.object(m,'MAX_GRAPH_METADATA',1):self.assertRaises(m.SourceError,store.__getitem__,'p0999')
    def test_real_final_fsync_late_publication_rejects(self):
        original=m.os.fsync
        def delayed(fd):result=original(fd);time.sleep(.04);return result
        with mock.patch.object(m.os,'fsync',side_effect=delayed):self.assertRaises(TimeoutError,m._publish_new,self.root,'delayed',b'actual bytes',time.monotonic()+.02)
    def test_index_manifest_and_candidate_splice_is_held(self):
        store=self.store({});index=dict(schema='org.trillionnium.owner-git-content-index.v1',profile_id=m.PROFILE,candidate=dict(self.graph[0],control_regular_files=1595),resolved_manifest_sha256=m.sha(self.graph[1]),projects=[dict(project=p,record=r) for p,r in dict.items(store)])
        self.assertRaises(m.SourceError,m.InventoryStore,index,self.graph[0],self.graph[1],self.graph[5],time.monotonic()+2)
    def test_duplicate_project_namespace_is_held(self):
        store=self.store({});entries=[dict(project=p,record=r) for p,r in dict.items(store)];entries[-1]=entries[0];index=dict(schema='org.trillionnium.owner-git-content-index.v1',profile_id=m.PROFILE,candidate=self.graph[0],resolved_manifest_sha256=m.sha(self.graph[1]),projects=entries)
        self.assertRaises(m.SourceError,m.InventoryStore,index,self.graph[0],self.graph[1],self.graph[5],time.monotonic()+2)

class ProjectionMappingTests(unittest.TestCase):
    def test_tracked_link_through_verified_directory_projection_closed(self):
        invs={'build/make':inventory([('core/input.mk',b'input','100644')]),'ordinary':inventory([('link',b'../build/core/input.mk','120000')])};projection=[dict(project='build/make',source='core',destination='build/core',kind='linkfile')];m.source_link_closure(invs,projection)
    def test_same_link_without_measured_projection_is_held(self):
        invs={'build/make':inventory([('core/input.mk',b'input','100644')]),'ordinary':inventory([('link',b'../build/core/input.mk','120000')])};self.assertRaises(m.SourceError,m.source_link_closure,invs)
    def test_projection_does_not_map_unknown_directory_member(self):
        invs={'build/make':inventory([('core/input.mk',b'input','100644')]),'ordinary':inventory([('link',b'../build/core/missing.mk','120000')])};projection=[dict(project='build/make',source='core',destination='build/core',kind='linkfile')];self.assertRaises(m.SourceError,m.source_link_closure,invs,projection)
    def test_standalone_actual_memory_limit_in_owned_child(self):
        code='import sys,resource;sys.path.insert(0,sys.argv[1]);import owner_source_provenance as m;m.bound_standalone_memory(256);print(resource.getrlimit(resource.RLIMIT_AS))'
        result=subprocess.run([sys.executable,'-c',code,str(TOOLS)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5);self.assertEqual(result.returncode,0,result.stderr);self.assertIn(str(256*1024*1024).encode(),result.stdout)
    def test_invalid_memory_limits_rejected_before_mutation(self):
        for limit in (False,0,255,4097):
            with self.subTest(limit=limit):self.assertRaises(m.SourceError,m.bound_standalone_memory,limit)

class CompletePacketMechanismTests(unittest.TestCase):
    """All1170 physical fragment files are synthetic, not ROG observations."""
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name);cls.root.chmod(0o700);graph=graph_fixture();archive_stream=io.BytesIO()
        from owner_asb38_fixtures import synthetic_catalog,rebind_graph_archive_sha
        declared_bodies=synthetic_catalog(fixture_source_root(),m)[1]
        with tarfile.open(fileobj=archive_stream,mode='w:gz') as archive:
            for row in graph[2]['trillionnium-os']['source_files']:
                if row['path'] in (m.SOURCE_CHECKER,m.SDK_CHECKER):raw=(fixture_source_root()/row['path']).read_bytes()
                elif row['path'] in declared_bodies:raw=declared_bodies[row['path']]
                elif row['path'].startswith('android-integration/'):raw=b'owner source'
                else:raw=b'ordinary'
                assert m.sha(raw)==row['sha256'];member=tarfile.TarInfo(row['path']);member.mode=0o644;member.size=len(raw);archive.addfile(member,io.BytesIO(raw))
        archive=archive_stream.getvalue();digest=m.sha(archive)
        rebind_graph_archive_sha(graph,m,digest)
        graph[11]['source_archive']=dict(bytes=len(archive),sha256=digest);entries=[];deadline=time.monotonic()+60
        for number,(project,inv) in enumerate(graph[2].items()):
            directory=cls.root/('project-'+str(number));directory.mkdir(mode=0o700);entries.append(dict(project=project,record=m.publish_sharded_inventory(project,inv,directory,deadline)))
        index=dict(schema='org.trillionnium.owner-git-content-index.v1',profile_id=m.PROFILE,candidate=graph[0],resolved_manifest_sha256=m.sha(graph[1]),projects=entries)
        values={'resolved_manifest':graph[1],'control_archive':archive,'inventory_index':m.canonical(index),'canonical_custody':m.canonical(graph[11]),'original_before':m.canonical(graph[3]),'original_after':m.canonical(graph[4]),'manifest_repository_inventory':m.canonical(graph[6]),'motorola_blob_trees':m.canonical(graph[7]),'generated_source_delta':m.canonical(graph[8]),'owner_source_selection':m.canonical(graph[9]),'manifest_projections':m.canonical(graph[12]),'private_composition':m.canonical(graph[13])}
        documents={}
        for name,raw in values.items():path=cls.root/name;path.write_bytes(raw);path.chmod(0o600);documents[name]=desc(path)
        cls.packet=dict(schema=m.INPUT_SCHEMA,profile_id=m.PROFILE,candidate=graph[0],documents=documents,private_project_paths=graph[5]);cls.serial=0
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def packet_path(self,mutate=None):
        type(self).serial+=1;packet=copy.deepcopy(self.packet)
        if mutate:mutate(packet)
        path=self.root/('packet-'+str(self.serial));path.write_bytes(m.canonical(packet));path.chmod(0o600);return path
    def test_actual_full_fragment_reader_and_required_meta_materializer(self):
        value=m.inspect_packet(self.packet_path(),time.monotonic()+30);self.assertEqual(len(value['git_content_inventory_sha256']),1170);self.assertGreater(len(value['raw_project_evidence_descriptors']),3000);self.assertFalse(value['installed']);import verify_owner_target_files_binding as target;target.validate_bom(m.canonical(value))
    def test_missing_projection_input_is_held(self):
        path=self.packet_path(lambda p:p['documents'].pop('manifest_projections'));self.assertRaises(m.SourceError,m.inspect_packet,path,time.monotonic()+30)
    def test_missing_final_composition_input_is_held(self):
        path=self.packet_path(lambda p:p['documents'].pop('private_composition'));self.assertRaises(m.SourceError,m.inspect_packet,path,time.monotonic()+30)
    def test_canonical_custody_descriptor_splice_is_held(self):
        path=self.packet_path(lambda p:p['documents']['canonical_custody'].update(sha256='0'*64));self.assertRaises(m.SourceError,m.inspect_packet,path,time.monotonic()+30)
    def test_packet_whole_deadline_uses_real_clock(self):
        path=self.packet_path();original=m.validate_graph
        def delayed(*args):value=original(*args);time.sleep(.1);return value
        with mock.patch.object(m,'validate_graph',side_effect=delayed):self.assertRaises(TimeoutError,m.inspect_packet,path,time.monotonic()+.03)

if __name__=='__main__':unittest.main()
