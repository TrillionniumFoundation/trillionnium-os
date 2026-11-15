"""Packaging refusals use the real Android ELF without executing models."""
from pathlib import Path
import json,os,shutil,subprocess,sys,tempfile,unittest
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from verify_vlm_runtime import verify_vlm_runtime,verify_vlm_worker_dynamic

class VlmRuntime(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='hepta-vlm-package-',dir='/tmp')
        cls.root=Path(cls.temp.name)/'source';cls.runtime=Path(cls.temp.name)/'runtime'
        cls.runtime.mkdir();(cls.root/'native').mkdir(parents=True)
        shutil.copytree(ROOT/'native/vlm-worker',cls.root/'native/vlm-worker')
        for rel in ['native/local-vlm-runtime-pins.json','native/owned-generation.inc',
                    'provenance/ui-venus-app-r1/sdk-runtime-pins.json']:
            p=cls.root/rel;p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(ROOT/rel,p)
        cls.pins=json.loads((cls.root/'native/local-vlm-runtime-pins.json').read_text())
        m=cls.pins['worker'];cls.java=cls.root/'src/org/trillionnium/hepta/local/VlmPins.java'
        cls.java.parent.mkdir(parents=True)
        cls.java.write_text('class VlmPins { static final String WORKER="'+m['apk_name']+'"; '
            'static final String WORKER_SHA="'+m['sha256']+'"; static final long WORKER_BYTES='+str(m['bytes'])+'L; }\n')
        actual=Path(os.environ['HEPTA_TEST_VLM_RUNTIME'])
        for name in [m['source_name'],'BUILD-RECEIPT.json']:shutil.copyfile(actual/name,cls.runtime/name)
        cls.elf=subprocess.check_output(['readelf','-d',str(cls.runtime/m['source_name'])],text=True)
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()
    def mutate(self,path,data):
        original=path.read_bytes()
        try:
            path.write_bytes(data)
            with self.assertRaises(RuntimeError):self.verify()
        finally:path.write_bytes(original)
    def verify(self):return verify_vlm_runtime(self.root,self.runtime)
    def receipt_mutation(self,key,value):
        p=self.runtime/'BUILD-RECEIPT.json';data=json.loads(p.read_text());data[key]=value
        self.mutate(p,json.dumps(data).encode())
    def test_actual_independent_artifact(self):
        rows=self.verify();self.assertEqual(set(rows),{'libhepta_local_vlm_runner.so'})
        self.assertEqual(rows['libhepta_local_vlm_runner.so']['sha256'],self.pins['worker']['sha256'])
        verify_vlm_worker_dynamic(self.elf,self.pins['worker'])
    def test_worker_single_byte_mutation(self):
        p=self.runtime/self.pins['worker']['source_name'];data=bytearray(p.read_bytes());data[-1]^=1;self.mutate(p,data)
    def test_java_pin_mismatch(self):
        self.mutate(self.java,self.java.read_bytes().replace(self.pins['worker']['sha256'].encode(),b'0'*64))
    def test_native_source_mutation(self):
        p=self.root/'native/vlm-worker/native/vlm-worker.cpp';self.mutate(p,p.read_bytes()+b'\n// changed\n')
    def test_generation_cleanup_cannot_diverge(self):
        p=self.root/'native/owned-generation.inc';self.mutate(p,p.read_bytes()+b'\n')
    def test_build_cannot_claim_phone_acceptance(self):self.receipt_mutation('android_executed',True)
    def test_sdk_hash_change(self):
        p=self.runtime/'BUILD-RECEIPT.json';data=json.loads(p.read_text());data['runtime'][0]['sha256']='0'*64
        self.mutate(p,json.dumps(data).encode())
    def test_added_cpp_runtime(self):self.receipt_mutation('new_cpp_runtime_added',True)
    def test_vendor_closure_cannot_be_overclaimed(self):
        self.receipt_mutation('strong_undefined_closure_complete',True)
        proof=self.root/'native/vlm-worker/provenance/LINKED-BACKENDS-HOST-R5.json'
        self.mutate(proof,proof.read_bytes()+b'\n')
        original=json.loads((self.runtime/'BUILD-RECEIPT.json').read_text())
        for key,value in [('registration','dynamic_plugin'),('generic_plugin_entry_absent',False),
                          ('generic_plugin_entry_absent',1),('phone_registration_executed',True),
                          ('phone_registration_executed',0)]:
            with self.subTest(linked_backend_field=key,value=value):
                abi=dict(original['linked_backend_abi']);abi[key]=value
                self.receipt_mutation('linked_backend_abi',abi)
        abi=dict(original['linked_backend_abi']);abi['libraries']=dict(abi['libraries'])
        abi['libraries']['libggml-cpu.so']='ggml_backend_init'
        self.receipt_mutation('linked_backend_abi',abi)
        self.receipt_mutation('linked_backend_abi',None)
        for value in (None,True,0,24,23.0):
            with self.subTest(linked_backend_host_checks=value):
                self.receipt_mutation('linked_backend_host_checks',value)
        for value in (None,'','g'*64):
            with self.subTest(linked_backend_host_receipt_sha256=value):
                self.receipt_mutation('linked_backend_host_receipt_sha256',value)
    def test_rpath_and_foreign_runpath(self):
        for value in [self.elf.replace('(RUNPATH)','(RPATH)'),self.elf.replace('[$ORIGIN]','[/data/local/tmp]'),
                      self.elf.replace('[libllama-common.so]','[libc++_shared.so]')]:
            with self.assertRaises(RuntimeError):verify_vlm_worker_dynamic(value,self.pins['worker'])
    def test_source_manifest_mismatch(self):
        p=self.root/'native/vlm-worker/SOURCE.json';self.mutate(p,p.read_bytes()+b' ')

if __name__=='__main__':unittest.main()
