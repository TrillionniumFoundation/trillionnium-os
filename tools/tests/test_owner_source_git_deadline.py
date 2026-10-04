"""Finite Git query budgets on real local trees; no Android qualification."""
import importlib.util,json,os,subprocess,sys,tempfile,time,unittest
from pathlib import Path
from unittest import mock

TOOLS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(TOOLS))
import owner_source_provenance as p
VECTOR=TOOLS/'collect_owner_source_vector.py'
if not VECTOR.exists():VECTOR=TOOLS.parent/'extra-tools/collect_owner_source_vector.py'
spec=importlib.util.spec_from_file_location('query_deadline_vector',VECTOR)
v=importlib.util.module_from_spec(spec);spec.loader.exec_module(v)

class QueryDeadlineTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name)/'repo';self.root.mkdir()
        self.env=dict(os.environ,GIT_AUTHOR_NAME='Local Fixture',GIT_AUTHOR_EMAIL='fixture@local.invalid',GIT_COMMITTER_NAME='Local Fixture',GIT_COMMITTER_EMAIL='fixture@local.invalid')
        self.git('init','-q');(self.root/'ordinary').write_bytes(b'actual source')
        self.git('add','.');self.git('-c','commit.gpgsign=false','commit','-qm','fixture')
        self.head=self.git('rev-parse','HEAD').decode().strip();self.tree=self.git('rev-parse','HEAD^{tree}').decode().strip()
        self.process=p.bounded_module(time.monotonic()+10)
    def tearDown(self):self.temp.cleanup()
    def git(self,*args):
        result=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-C',str(self.root),*args],env=self.env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr);return result.stdout
    def collect(self,kind,deadline,**kwargs):
        if kind=='vector':return v.observe_project(p,self.process,self.root,'project',self.head,deadline,**kwargs)
        with mock.patch.object(p,'bounded_module',return_value=self.process):
            return p.collect_git_checkout(self.root,self.head,self.tree,deadline,'project',**kwargs)
    def test_real_queries_keep_default_and_accept_finite_boundaries(self):
        original=self.process.run_bounded
        for kind in ('vector','inventory'):
            for limit in (None,1,120,300):
                with self.subTest(kind=kind,limit=limit):
                    seen=[]
                    def recorded(*args,**kwargs):
                        seen.append(kwargs['timeout_seconds']);return original(*args,**kwargs)
                    kwargs={} if limit is None else dict(git_query_seconds=limit)
                    with mock.patch.object(self.process,'run_bounded',side_effect=recorded):self.collect(kind,time.monotonic()+600,**kwargs)
                    self.assertGreaterEqual(len(seen),5);self.assertTrue(all(value==(30 if limit is None else limit) for value in seen))
    def test_remaining_whole_deadline_caps_first_query(self):
        class Captured(Exception):pass
        for kind in ('vector','inventory'):
            seen=[]
            def recorded(*args,**kwargs):seen.append(kwargs['timeout_seconds']);raise Captured()
            deadline=time.monotonic()+.5
            with mock.patch.object(self.process,'run_bounded',side_effect=recorded):
                with self.assertRaises(Captured):self.collect(kind,deadline,git_query_seconds=120)
            self.assertEqual(len(seen),1);self.assertGreater(seen[0],0);self.assertLessEqual(seen[0],.5)
    def test_invalid_library_limits_reject_before_git_or_packet_read(self):
        for value in (True,False,None,'120',0,.5,301,float('nan'),float('inf'),-float('inf'),10**1000):
            for kind in ('vector','inventory'):
                with self.subTest(value=repr(value),kind=kind),mock.patch.object(self.process,'run_bounded') as run:
                    with self.assertRaisesRegex(p.SourceError,'finite 1..300'):self.collect(kind,time.monotonic()+10,git_query_seconds=value)
                    run.assert_not_called()
            with mock.patch.object(p,'read_stable') as read:
                with self.assertRaisesRegex(p.SourceError,'finite 1..300'):v.inspect_packet(p,Path('/unread/deadline-packet'),time.monotonic()+10,value)
                read.assert_not_called()
    def test_actual_timed_out_child_keeps_git_subject_and_cleanup_diagnostics(self):
        original=self.process.run_bounded
        for kind in ('vector','inventory'):
            # Retain the collector's Git argument context while exercising the
            # actual bounded supervisor with a real delayed child.
            def delayed(argv,**kwargs):
                return original([sys.executable,'-c','import time;time.sleep(3)'],**kwargs)
            with mock.patch.object(self.process,'run_bounded',side_effect=delayed):
                with self.assertRaises(p.SourceError) as caught:self.collect(kind,time.monotonic()+10,git_query_seconds=1)
            message=str(caught.exception)
            self.assertIn("project='project'",message);self.assertIn("argv=['config'",message)
            self.assertIn('actual_rc=-9',message);self.assertIn("'timed_out': True",message)
            self.assertIn("'cleanup_error': False",message);self.assertIn("'capture_error': False",message)
    def test_cli_invalid_limits_return_truthful_hold(self):
        for path,args in ((TOOLS/'owner_source_provenance.py',['collect-git',str(self.root),self.head,self.tree]),(VECTOR,[str(self.root/'not-read-packet')])):
            for value in ('0','301','nan','inf'):
                result=subprocess.run([sys.executable,str(path),*args,'--git-query-seconds',value],stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
                self.assertEqual(result.returncode,2,result.stderr);body=json.loads(result.stdout)
                self.assertIn('finite 1..300',body['error']);self.assertFalse(body['source_bom_qualified']);self.assertFalse(body['production_ready'])

if __name__=='__main__':unittest.main()
