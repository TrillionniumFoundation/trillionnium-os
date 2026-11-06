"""Synthetic META/ZIP splice controls; no actual Android output measured here."""
import copy,hashlib,io,json,os,subprocess,sys,tempfile,time,unittest,zipfile
from pathlib import Path
from unittest import mock
TOOLS=Path(__file__).resolve().parents[1];sys.path.insert(0,str(TOOLS))
import owner_source_provenance as p
import verify_owner_target_files_binding as m
p=m.p  # The checker executes its measured sibling in its own namespace.
from test_owner_source_provenance import graph_fixture

def bom_fixture():
    graph=graph_fixture(provenance=p);bom=p.validate_graph(*graph);names=('resolved_manifest','control_archive','inventory_index','canonical_custody','original_before','original_after','manifest_repository_inventory','motorola_blob_trees','generated_source_delta','owner_source_selection','manifest_projections','private_composition')
    bom['input_packet_sha256']='b'*64;bom['input_descriptors']={name:dict(path='/unexecuted/mechanism/'+name,bytes=1,sha256='c'*64) for name in names}
    bom['input_descriptors']['resolved_manifest']['sha256']=bom['manifest_sha256'];bom['input_descriptors']['control_archive']['sha256']=bom['candidate']['archive_sha256'];bom['input_descriptors']['canonical_custody']['sha256']=bom['canonical_custody_sha256'];bom['input_descriptors']['manifest_projections']['sha256']=bom['manifest_projection_observations_sha256'];bom['input_descriptors']['private_composition']['sha256']=bom['private_composition_sha256'];bom['raw_project_evidence_descriptors']=[dict(path='/unexecuted/mechanism/project'+str(i),bytes=1,sha256='d'*64) for i in range(p.MANIFEST_COUNT)];bom['whole_measured_tracked_files']=sum(len(v['source_files']) for v in graph[2].values());bom['whole_source_metadata_bytes']=1;bom['receipt_id']='sha256:'+p.sha(p.canonical(bom));raw=p.canonical(bom)
    build=dict(schema='org.trillionnium.owner-android-build-source-inputs.v1',candidate=bom['candidate'],resolved_manifest_sha256=bom['manifest_sha256'],owner_source_bom_sha256=p.sha(raw),stage_id='mechanism-fixture-not-Android')
    return bom,raw,build
def zip_bytes(entries):
    stream=io.BytesIO()
    with zipfile.ZipFile(stream,'w') as z:
        for name,body in entries:z.writestr(name,body)
    return stream.getvalue()
def actual_descriptor(body):return dict(bytes=len(body),sha256=p.sha(body))

class OwnerMetaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.bom,cls.raw,cls.build=bom_fixture()
    def body(self):return zip_bytes([(m.MEMBER,p.canonical(m.materialize_binding(self.raw,self.build))),('SYSTEM/etc/fixture',b'ordinary')])
    def inspect(self,body,expected=None):return m.inspect_stream(io.BytesIO(body),self.raw,self.build,expected or actual_descriptor(body),time.monotonic()+5)
    def test_required_owner_meta_and_whole_zip_positive_mechanism(self):
        value=self.inspect(self.body());self.assertTrue(value['required_owner_meta_binding_verified']);self.assertFalse(value['installed']);self.assertFalse(value['release_signature_verified'])
    def test_absent_meta_held(self):self.assertRaises(p.SourceError,self.inspect,zip_bytes([('SYSTEM/etc/fixture',b'ordinary')]))
    def test_old_p0_meta_not_substitute(self):self.assertRaises(p.SourceError,self.inspect,zip_bytes([('META/trillionnium-source-bom-binding.json',b'{}')]))
    def test_duplicate_member_rejected(self):
        raw=p.canonical(m.materialize_binding(self.raw,self.build));self.assertRaises(p.SourceError,self.inspect,zip_bytes([(m.MEMBER,raw),(m.MEMBER,raw)]))
    def test_zip_splice_same_meta_other_payload_rejected(self):
        first=self.body();second=zip_bytes([(m.MEMBER,p.canonical(m.materialize_binding(self.raw,self.build))),('SYSTEM/etc/fixture',b'changed')]);self.assertRaises(p.SourceError,self.inspect,second,actual_descriptor(first))
    def test_wrong_candidate_inside_meta_rejected(self):
        value=m.materialize_binding(self.raw,self.build);value['candidate']['commit']='0'*40;self.assertRaises(p.SourceError,self.inspect,zip_bytes([(m.MEMBER,p.canonical(value))]))
    def test_wrong_build_stage_receipt_rejected(self):
        build=copy.deepcopy(self.build);build['stage_id']='other';value=m.materialize_binding(self.raw,build);self.assertRaises(p.SourceError,self.inspect,zip_bytes([(m.MEMBER,p.canonical(value))]))
    def test_source_bom_missing_inventory_rejected(self):
        bom=copy.deepcopy(self.bom);bom['git_content_inventory_sha256'].pop('p0999');bom.pop('receipt_id');bom['receipt_id']='sha256:'+p.sha(p.canonical(bom));self.assertRaises(p.SourceError,m.validate_bom,p.canonical(bom))
    def test_source_bom_old_schema_rejected(self):
        bom=copy.deepcopy(self.bom);bom['schema']='org.trillionnium.local-cross-repo-source-bom.v2';self.assertRaises(p.SourceError,m.validate_bom,p.canonical(bom))
    def test_owner_v2_schema_or_profile_cannot_be_mixed_with_v3(self):
        for changed in (dict(schema='org.trillionnium.owner-source-bom.v2'),dict(profile_id='owner-open-whole-control-v2')):
            with self.subTest(changed=changed):
                bom=copy.deepcopy(self.bom);bom.update(changed);bom.pop('receipt_id');bom['receipt_id']='sha256:'+p.sha(p.canonical(bom))
                with self.assertRaisesRegex(p.SourceError,'qualified owner graph receipt required'):m.validate_bom(p.canonical(bom))
    def test_old15_or_unrelated_sixteenth_private_project_is_held(self):
        for replacement in (None,'p0000'):
            with self.subTest(replacement=replacement):
                bom=copy.deepcopy(self.bom);paths=bom['private_project_paths'];paths.remove('packages/modules/Nfc')
                if replacement is not None:paths.append(replacement)
                bom.pop('receipt_id');bom['receipt_id']='sha256:'+p.sha(p.canonical(bom));self.assertRaises(p.SourceError,m.validate_bom,p.canonical(bom))
    def test_source_bom_bad_content_id(self):
        bom=copy.deepcopy(self.bom);bom['receipt_id']='sha256:'+'0'*64;self.assertRaises(p.SourceError,m.validate_bom,p.canonical(bom))
    def test_source_bom_production_claim_rejected(self):
        bom=copy.deepcopy(self.bom);bom['production_ready']=True;self.assertRaises(p.SourceError,m.validate_bom,p.canonical(bom))
    def test_nonatomic_observation_scope_must_be_typed_true(self):
        for marker in (False,1,'true',None):
            with self.subTest(marker=marker):
                bom=copy.deepcopy(self.bom);bom['observations_sequential_not_globally_atomic']=marker;bom.pop('receipt_id');bom['receipt_id']='sha256:'+p.sha(p.canonical(bom));self.assertRaises(p.SourceError,m.validate_bom,p.canonical(bom))
    def test_build_stage_rejects_unicode_and_non_ascii_space(self):
        for stage in ('阶段','buildé','stage\u200bname','stage name',''):
            with self.subTest(stage=stage):self.assertRaises(p.SourceError,m.materialize_binding,self.raw,dict(self.build,stage_id=stage))
    def test_unsafe_zip_member_rejected(self):self.assertRaises(p.SourceError,self.inspect,zip_bytes([(m.MEMBER,p.canonical(m.materialize_binding(self.raw,self.build))),('../escape',b'not opened')]))
    def test_symlink_meta_rejected(self):
        stream=io.BytesIO()
        with zipfile.ZipFile(stream,'w') as z:
            info=zipfile.ZipInfo(m.MEMBER);info.create_system=3;info.external_attr=(0o120777<<16);z.writestr(info,p.canonical(m.materialize_binding(self.raw,self.build)))
        self.assertRaises(p.SourceError,self.inspect,stream.getvalue())
    def test_duplicate_json_member_rejected(self):
        self.assertRaises(p.SourceError,self.inspect,zip_bytes([(m.MEMBER,b'{"schema":"a","schema":"b"}')]))
    def test_real_path_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp);actual=root/'target.zip';actual.write_bytes(self.body());alias=root/'alias';alias.symlink_to(actual);self.assertRaises(p.SourceError,m.inspect_path,alias,self.raw,self.build,actual_descriptor(actual.read_bytes()),time.monotonic()+2)
    def test_final_hash_actual_delay_rejected(self):
        body=self.body();original=m.hashlib.sha256
        class Late:
            def __init__(self,*args,**kwargs):self.h=original(*args,**kwargs)
            def update(self,b):self.h.update(b)
            def hexdigest(self):result=self.h.hexdigest();time.sleep(.04);return result
        # The same real SHA bytes are retained; only the callback completion is
        # delayed with the real monotonic clock. It must not return a PASS.
        with mock.patch.object(m.hashlib,'sha256',side_effect=Late):self.assertRaises(TimeoutError,m.inspect_stream,io.BytesIO(body),self.raw,self.build,actual_descriptor(body),time.monotonic()+.02)

def fixture_makefile():
    root=TOOLS.parent
    path=root/'android-integration/working-tree/build/make/core/Makefile'
    if not path.is_file():
        value=os.environ.get('OWNER_BOM_FIXTURE_MAKEFILE_ROOT')
        p.require(type(value) is str and Path(value).is_absolute(),'explicit staging Makefile fixture root required')
        path=Path(value)/'android-integration/working-tree/build/make/core/Makefile'
    text=p.read_stable(path,1024*1024,time.monotonic()+10).decode()
    start=text.index('# Owner source-BOM is required only for the dedicated owner-open product.')
    end=text.index('# Depending on the various images guarantees',start)
    selector=text[start:end]
    start=text.index('ifneq ($(_trillionnium_owner_bom_selected),)\n\t@# Publish')
    end=text.index('\t$(hide) cp $(APKCERTS_FILE)',start)
    return selector,text[start:end]

class BuildMetaPublicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.bom,cls.raw,cls.build=bom_fixture()
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.root.chmod(0o700);self.meta=self.root/'META';self.meta.mkdir(mode=0o700);self.bom_path=self.root/'bom.json';self.build_path=self.root/'build.json';self.binding_path=self.root/'binding.json';self.bom_path.write_bytes(self.raw);self.build_path.write_bytes(p.canonical(self.build));self.binding_path.write_bytes(p.canonical(m.materialize_binding(self.raw,self.build)))
    def tearDown(self):self.temp.cleanup()
    def stage(self):return m.stage_binding(self.bom_path,self.build_path,self.binding_path,self.meta,time.monotonic()+5)
    def test_actual_new_meta_inode_and_preserved_raw_input(self):
        value=self.stage();path=self.meta/Path(m.MEMBER).name;self.assertEqual(path.read_bytes(),self.binding_path.read_bytes());self.assertEqual(path.stat().st_mode&0o777,0o600);self.assertFalse(value['zip_modified']);self.assertFalse(value['installed'])
    def test_existing_meta_is_not_overwritten(self):
        path=self.meta/Path(m.MEMBER).name;path.write_bytes(b'prior');self.assertRaises(FileExistsError,self.stage);self.assertEqual(path.read_bytes(),b'prior')
    def test_existing_meta_symlink_is_not_followed_or_overwritten(self):
        original=self.root/'original';original.write_bytes(b'prior');(self.meta/Path(m.MEMBER).name).symlink_to(original);self.assertRaises(FileExistsError,self.stage);self.assertEqual(original.read_bytes(),b'prior')
    def test_bad_binding_is_rejected_before_output(self):
        self.binding_path.write_bytes(b'{}');self.assertRaises(p.SourceError,self.stage);self.assertEqual(list(self.meta.iterdir()),[])
    def test_bad_build_tuple_is_rejected_before_output(self):
        value=copy.deepcopy(self.build);value['candidate']['commit']='0'*40;self.build_path.write_bytes(p.canonical(value));self.assertRaises(p.SourceError,self.stage);self.assertEqual(list(self.meta.iterdir()),[])
    def test_real_build_cli_environment_is_checked(self):
        env=dict(os.environ,TRILLINNIUM_OWNER_SOURCE_BOM_JSON=str(self.bom_path),TRILLINNIUM_OWNER_SOURCE_BUILD_INPUTS_JSON=str(self.build_path),TRILLINNIUM_OWNER_SOURCE_BOM_BINDING_JSON=str(self.binding_path));r=subprocess.run([sys.executable,str(TOOLS/'verify_owner_target_files_binding.py'),'stage-binding-env','--meta-directory',str(self.meta)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(json.loads(r.stdout)['meta_file']['sha256'],p.sha(self.binding_path.read_bytes()))
    def test_real_build_cli_missing_environment_fails_nonzero(self):
        env={k:v for k,v in os.environ.items() if not k.startswith('TRILLINNIUM_OWNER_SOURCE_')};r=subprocess.run([sys.executable,str(TOOLS/'verify_owner_target_files_binding.py'),'stage-binding-env','--meta-directory',str(self.meta)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(r.returncode,2,r.stderr);self.assertFalse(json.loads(r.stdout)['owner_binding_published']);self.assertEqual(list(self.meta.iterdir()),[])
    def test_actual_make_owner_selector_and_sealed_default(self):
        selector,_=fixture_makefile()
        for enabled,inputs,expected in ((False,False,0),(True,False,2),(True,True,0)):
            with self.subTest(enabled=enabled,inputs=inputs):
                stamp=self.root/('stamp-'+str(enabled)+'-'+str(inputs));mk=self.root/'fixture.mk';text='BUILT_TARGET_FILES_DIR := '+str(stamp)+'\nPRODUCT_SYSTEM_EXT_PROPERTIES := '+('ro.trillionnium.owner_open.enabled=true' if enabled else 'ro.other.profile=sealed')+'\n'
                if inputs:text+='TRILLINNIUM_OWNER_SOURCE_BOM_JSON := '+str(self.bom_path)+'\nTRILLINNIUM_OWNER_SOURCE_BUILD_INPUTS_JSON := '+str(self.build_path)+'\nTRILLINNIUM_OWNER_SOURCE_BOM_BINDING_JSON := '+str(self.binding_path)+'\n'
                text+=selector+'\n'+str(stamp)+':\n\t@touch $@\n';mk.write_text(text)
                # The same three admitted Python files are concrete Make
                # prerequisites. These are physical byte-exact fixture copies, not an Android
                # graph or source-BOM qualification claim.
                destination=self.root/'trillionnium-os/tools';destination.mkdir(parents=True,exist_ok=True)
                for name in ('verify_owner_target_files_binding.py','owner_source_provenance.py','owner_bom_bounded_process.py'):
                    path=destination/name
                    if not path.exists():path.write_bytes((TOOLS/name).read_bytes())
                    self.assertEqual(path.read_bytes(),(TOOLS/name).read_bytes())
                r=subprocess.run(['/usr/bin/make','--no-print-directory','-f',str(mk),str(stamp)],cwd=self.root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(r.returncode,expected,r.stderr);self.assertEqual(stamp.exists(),expected==0)
    def test_actual_make_writer_before_zip_and_strict_meta_observer(self):
        overlay=TOOLS.parents[0]/'android-integration/working-tree/build/make/core/Makefile';text=overlay.read_text();start=text.index('ifneq ($(_trillionnium_owner_bom_selected),)\n\t@# Publish');end=text.index('\t$(hide) cp $(APKCERTS_FILE)',start);writer=text[start:end];selector,_=fixture_makefile();zip_root=self.root/'zip-root';stamp=self.root/'stamp';mk=self.root/'fixture.mk';destination=self.root/'trillionnium-os/tools';destination.mkdir(parents=True)
        for name in ('verify_owner_target_files_binding.py','owner_source_provenance.py','owner_bom_bounded_process.py'):
            (destination/name).write_bytes((TOOLS/name).read_bytes());self.assertEqual((destination/name).read_bytes(),(TOOLS/name).read_bytes())
        source='BUILT_TARGET_FILES_DIR := '+str(stamp)+'\nPRODUCT_SYSTEM_EXT_PROPERTIES := ro.trillionnium.owner_open.enabled=true\nzip_root := '+str(zip_root)+'\nhide := @\nTRILLINNIUM_OWNER_SOURCE_BOM_JSON := '+str(self.bom_path)+'\nTRILLINNIUM_OWNER_SOURCE_BUILD_INPUTS_JSON := '+str(self.build_path)+'\nTRILLINNIUM_OWNER_SOURCE_BOM_BINDING_JSON := '+str(self.binding_path)+'\n'+selector+'\n'+str(stamp)+':\n\t$(hide) mkdir -p $(zip_root)/META\n'+writer+'\t$(hide) touch $@\n';mk.write_text(source);r=subprocess.run(['/usr/bin/make','--no-print-directory','-f',str(mk),str(stamp)],cwd=self.root,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10);self.assertEqual(r.returncode,0,r.stderr)
        body=zip_bytes([(m.MEMBER,(zip_root/m.MEMBER).read_bytes()),('SYSTEM/etc/fixture',b'ordinary')]);actual=self.root/'target-files-fixture.zip';actual.write_bytes(body);result=m.inspect_path(actual,self.raw,self.build,actual_descriptor(body),time.monotonic()+5);self.assertTrue(result['required_owner_meta_binding_verified']);self.assertFalse(result['installed'])

if __name__=='__main__':unittest.main()
