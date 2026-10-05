"""Actual local Git/no-filter queries; no ROG or Android qualification."""
import base64,copy,importlib.util,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock
SOURCE=Path(__file__).resolve().parents[1]/'collect_owner_source_vector.py';spec=importlib.util.spec_from_file_location('vector_observer_fixture',SOURCE);v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v);m,_,_=v.load_source()
sys.path.insert(0,str(SOURCE.parents[1]/'tools/tests'));from test_owner_source_provenance import graph_fixture

class ActualGitVectorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'project';self.root.mkdir();self.env=dict(os.environ,GIT_CONFIG_GLOBAL='/dev/null',GIT_CONFIG_NOSYSTEM='1',GIT_AUTHOR_NAME='Fixture',GIT_AUTHOR_EMAIL='fixture@local.invalid',GIT_COMMITTER_NAME='Fixture',GIT_COMMITTER_EMAIL='fixture@local.invalid');self.git('init','-q');(self.root/'ordinary').write_bytes(b'actual ordinary');self.commit();self.process=m.bounded_module(time.monotonic()+10)
    def tearDown(self):self.temp.cleanup()
    def git(self,*args):
        r=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','filter.lfs.clean=','-c','filter.lfs.smudge=','-c','filter.lfs.process=','-c','filter.lfs.required=false','-C',str(self.root),*args],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5);self.assertEqual(r.returncode,0,r.stderr);return r.stdout
    def commit(self):self.git('add','.');self.git('-c','commit.gpgsign=false','commit','-qm','fixture');self.head=self.git('rev-parse','HEAD').decode().strip();self.tree=self.git('rev-parse','HEAD^{tree}').decode().strip()
    def observe(self):return v.observe_project(m,self.process,self.root,'project',self.head,time.monotonic()+10)
    def test_actual_clean_generation_raw_status_and_no_write(self):
        before=(self.root/'.git/index').read_bytes();row=self.observe();self.assertEqual(row['head'],self.head);self.assertEqual(row['tree'],self.tree);self.assertEqual(row['git_status_bytes'],0);self.assertEqual((self.root/'.git/index').read_bytes(),before)
    def test_actual_ordinary_dirty_retained_and_inventory_rejects(self):
        (self.root/'ordinary').write_bytes(b'actual dirty');row=self.observe();self.assertEqual(base64.b64decode(row['raw_git_status_base64']),b' M ordinary\0');self.assertRaises(m.SourceError,m.collect_git_checkout,self.root,self.head,self.tree,time.monotonic()+10)
    def test_actual_lfs_same_policy_as_full_content_collector(self):
        payload=b'PK\x03\x04'+b'actual payload'*4000;pointer=('version https://git-lfs.github.com/spec/v1\noid sha256:'+m.sha(payload)+'\nsize '+str(len(payload))+'\n').encode();(self.root/'.gitattributes').write_bytes(b'*.bin filter=lfs -text\n');(self.root/'webview.bin').write_bytes(pointer);self.commit();(self.root/'webview.bin').write_bytes(payload);marker=Path(self.temp.name)/'filter-executed'
        for key in ('clean','smudge','process'):self.git('config','filter.lfs.'+key,'touch '+str(marker))
        self.git('config','core.fsmonitor','touch '+str(marker));row=self.observe();inventory=m.collect_git_checkout(self.root,self.head,self.tree,time.monotonic()+10);self.assertEqual(row['raw_git_status_base64'],inventory['raw_status_before_base64']);self.assertEqual(base64.b64decode(row['raw_git_status_base64']),b' M webview.bin\0');self.assertFalse(marker.exists())
    def test_untracked_and_ignored_status_not_hidden(self):
        (self.root/'.gitignore').write_bytes(b'generated\n');self.commit();(self.root/'generated').write_bytes(b'generated');(self.root/'untracked').write_bytes(b'untracked');raw=base64.b64decode(self.observe()['raw_git_status_base64']);self.assertIn(b'!! generated\0',raw);self.assertIn(b'?? untracked\0',raw)
    def test_wrong_expected_head_is_held(self):self.assertRaises(m.SourceError,v.observe_project,m,self.process,self.root,'project','0'*40,time.monotonic()+10)
    def test_actual_git_failure_retains_logical_project_returncode_and_stderr(self):
        (self.root/'.git/config').write_bytes(b'[core\n')
        expected=subprocess.run(['/usr/bin/git','-C',str(self.root),'config','--local','--name-only','--get-regexp',r'^filter\.'],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=5)
        self.assertNotEqual(expected.returncode,0)
        with self.assertRaises(m.SourceError) as caught:self.observe()
        message=str(caught.exception);self.assertIn("project='project'",message);self.assertIn('actual_rc='+str(expected.returncode),message)
        self.assertIn('stderr_bytes='+str(len(expected.stderr)),message);self.assertIn('stderr_sha256='+m.sha(expected.stderr),message)
    def test_actual_project_symlink_is_held(self):
        alias=Path(self.temp.name)/'alias';alias.symlink_to(self.root);self.assertRaises(m.SourceError,v.observe_project,m,self.process,alias,'project',self.head,time.monotonic()+10)
    def test_real_late_builtin_query_rejects_deadline(self):
        original=self.process.run_bounded
        def delayed(*args,**kwargs):result=original(*args,**kwargs);time.sleep(.05);return result
        with mock.patch.object(self.process,'run_bounded',side_effect=delayed):self.assertRaises(TimeoutError,v.observe_project,m,self.process,self.root,'project',self.head,time.monotonic()+.02)

class VectorPacketBoundaryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.graph=graph_fixture(provenance=m)
    def test_all_original1153_physical_roots_required_before_query(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);manifest=root/'manifest';manifest.write_bytes(self.graph[1]);composition=root/'composition';composition.write_bytes(m.canonical(self.graph[13]));packet=root/'packet';value=dict(schema=v.INPUT_SCHEMA,profile_id=m.PROFILE,candidate=self.graph[0],resolved_manifest=m.descriptor(manifest,manifest.read_bytes()),private_composition=m.descriptor(composition,composition.read_bytes()),original_source_root=str(root),original_repository_paths=[]);packet.write_bytes(m.canonical(value));self.assertRaises(m.SourceError,v.inspect_packet,m,packet,time.monotonic()+5)
    def test_pinned3_module_byte_load_is_actual(self):
        module,directory,raws=v.load_source();self.assertEqual(module.PROFILE,'owner-open-whole-control-v4');self.assertEqual(set(raws),set(v.MODULE_SHAS))
    def test_old_v2_vector_profile_rejected_before_documents_or_git(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'packet';path.write_bytes(m.canonical(dict(schema=v.INPUT_SCHEMA,profile_id='owner-open-whole-control-v2',candidate={},resolved_manifest={},private_composition={},original_source_root=str(Path(temp)),original_repository_paths=[])))
            with self.assertRaisesRegex(m.SourceError,'distinct vector owner input/profile required'):v.inspect_packet(m,path,time.monotonic()+1)

if __name__=='__main__':unittest.main()
