"""Actual timestamp cache bodies must never replace measured module bytes."""
import hashlib, importlib.util, json, marshal, os, shutil, struct, subprocess, sys
import tempfile, unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
VECTOR = TOOLS/'collect_owner_source_vector.py'
if not VECTOR.exists(): VECTOR = TOOLS.parent/'extra-tools/collect_owner_source_vector.py'

class ActualMeasuredModuleLoaderTests(unittest.TestCase):
    def fixture(self, directory):
        for name in ('owner_source_provenance.py','owner_bom_bounded_process.py','verify_owner_target_files_binding.py'):
            shutil.copyfile(TOOLS/name,directory/name)
        shutil.copyfile(VECTOR,directory/'collect_owner_source_vector.py')

    def poisoned_timestamp_cache(self,path,marker):
        raw=path.read_bytes(); value=path.stat()
        compiled=compile(raw+('\n'+marker+' = True\n').encode(),str(path),'exec')
        cache=Path(importlib.util.cache_from_source(str(path)))
        cache.parent.mkdir(exist_ok=True)
        cache.write_bytes(importlib.util.MAGIC_NUMBER+struct.pack('<III',0,int(value.st_mtime)&0xffffffff,value.st_size)+marshal.dumps(compiled))
        return hashlib.sha256(raw).hexdigest()

    def run_real(self,directory,body):
        script=directory/'invoke.py';script.write_text(body)
        run=subprocess.run([sys.executable,str(script)],env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
        self.assertEqual(run.returncode,0,run.stderr.decode());return json.loads(run.stdout)

    def test_bounded_module_ignores_actual_matching_timestamp_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            helper=root/'owner_bom_bounded_process.py';digest=self.poisoned_timestamp_cache(helper,'_peer_cache_body')
            control=self.run_real(root,"import owner_bom_bounded_process as h,json\nprint(json.dumps(dict(marker=getattr(h,'_peer_cache_body',False))))\n")
            self.assertTrue(control['marker'],'negative control cache must really execute')
            actual=self.run_real(root,"import owner_source_provenance as p,time,json\nh=p.bounded_module(time.monotonic()+5)\nprint(json.dumps(dict(marker=getattr(h,'_peer_cache_body',False))))\n")
            self.assertFalse(actual['marker']);self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(),digest)

    def test_vector_ignores_actual_source_and_helper_timestamp_caches(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            source=root/'owner_source_provenance.py';helper=root/'owner_bom_bounded_process.py'
            source_digest=self.poisoned_timestamp_cache(source,'_peer_source_cache_body')
            helper_digest=self.poisoned_timestamp_cache(helper,'_peer_helper_cache_body')
            control=self.run_real(root,"import owner_source_provenance as p,owner_bom_bounded_process as h,json\nprint(json.dumps(dict(source=getattr(p,'_peer_source_cache_body',False),helper=getattr(h,'_peer_helper_cache_body',False))))\n")
            self.assertTrue(control['source']);self.assertTrue(control['helper'])
            actual=self.run_real(root,"import collect_owner_source_vector as v,time,json\np,_,_=v.load_source();h=p.bounded_module(time.monotonic()+5)\nprint(json.dumps(dict(source=getattr(p,'_peer_source_cache_body',False),helper=getattr(h,'_peer_helper_cache_body',False))))\n")
            self.assertFalse(actual['source']);self.assertFalse(actual['helper'])
            self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),source_digest)
            self.assertEqual(hashlib.sha256(helper.read_bytes()).hexdigest(),helper_digest)

    def test_checker_library_ignores_cache_and_ambient_module(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root)
            source=root/'owner_source_provenance.py';digest=self.poisoned_timestamp_cache(source,'_peer_source_cache_body')
            control=self.run_real(root,"import owner_source_provenance as p,json\nprint(json.dumps(dict(marker=getattr(p,'_peer_source_cache_body',False))))\n")
            self.assertTrue(control['marker'])
            actual=self.run_real(root,"import sys,types,json\nambient=types.ModuleType('owner_source_provenance');ambient.PROFILE='ambient unbound body';sys.modules['owner_source_provenance']=ambient\nimport verify_owner_target_files_binding as c\nprint(json.dumps(dict(profile=c.p.PROFILE,marker=getattr(c.p,'_peer_source_cache_body',False),ambient_used=c.p is ambient)))\n")
            self.assertEqual(actual['profile'],'owner-open-whole-control-v3');self.assertFalse(actual['marker']);self.assertFalse(actual['ambient_used']);self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),digest)

    def test_actual_meta_cli_ignores_timestamp_cache_during_publication(self):
        from test_verify_owner_target_files_binding import bom_fixture
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);meta=root/'META';meta.mkdir(mode=0o700)
            marker=root/'cache-body-executed';source=root/'owner_source_provenance.py';raw=source.read_bytes();before=hashlib.sha256(raw).hexdigest();value=source.stat()
            code=compile(raw+("\nPath("+repr(str(marker))+").write_text('unmeasured cache body')\n").encode(),str(source),'exec');cache=Path(importlib.util.cache_from_source(str(source)));cache.parent.mkdir(exist_ok=True);cache.write_bytes(importlib.util.MAGIC_NUMBER+struct.pack('<III',0,int(value.st_mtime)&0xffffffff,value.st_size)+marshal.dumps(code))
            self.run_real(root,"import owner_source_provenance,json\nprint(json.dumps(dict(loaded=True)))\n");self.assertTrue(marker.exists());marker.unlink()
            _,bom,build=bom_fixture();bom_path=root/'bom.json';build_path=root/'build.json';binding_path=root/'binding.json';bom_path.write_bytes(bom)
            sys.path.insert(0,str(TOOLS));import verify_owner_target_files_binding as checker
            build_path.write_bytes(checker.p.canonical(build));binding_path.write_bytes(checker.p.canonical(checker.materialize_binding(bom,build)))
            env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',TRILLINNIUM_OWNER_SOURCE_BOM_JSON=str(bom_path),TRILLINNIUM_OWNER_SOURCE_BUILD_INPUTS_JSON=str(build_path),TRILLINNIUM_OWNER_SOURCE_BOM_BINDING_JSON=str(binding_path))
            run=subprocess.run([sys.executable,str(root/'verify_owner_target_files_binding.py'),'stage-binding-env','--meta-directory',str(meta),'--seconds','10'],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=15)
            self.assertEqual(run.returncode,0,run.stderr.decode());self.assertFalse(marker.exists());self.assertEqual((meta/'trillionnium-owner-source-bom-binding.json').read_bytes(),binding_path.read_bytes());self.assertEqual(hashlib.sha256(source.read_bytes()).hexdigest(),before)

    def test_actual_meta_cli_refuses_symlink_dependency(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);self.fixture(root);source=root/'owner_source_provenance.py';raw=source.read_bytes();source.unlink();target=root/'source-elsewhere';target.write_bytes(raw);source.symlink_to(target)
            run=subprocess.run([sys.executable,str(root/'verify_owner_target_files_binding.py'),'--help'],env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1'),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10)
            self.assertNotEqual(run.returncode,0);self.assertIn(b'not physical',run.stderr);self.assertEqual(target.read_bytes(),raw)

if __name__=='__main__': unittest.main()
