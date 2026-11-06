"""Durable synthetic parser proofs and real disposable complete-clone tests.

No Android checkout, ROG, source fork qualification or release is measured.
All regular/symlink/executable/gitlink and LFS controls use finite local Git.
"""
import copy, hashlib, importlib.util, json, os, pathlib, subprocess, sys, tempfile, time, unittest
from unittest import mock
TOOLS=pathlib.Path(__file__).resolve().parents[1];sys.path.insert(0,str(TOOLS));sys.path.insert(0,str(TOOLS/'tests'))
import owner_asb_fork_catalog as c
import owner_source_provenance as p
import owner_source_surface as surface
import prepare_owner_asb_fullforks as producer
from owner_asb38_fixtures import synthetic_catalog,inventory,file_row
from test_owner_source_provenance import graph_fixture

class CatalogControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.catalog,cls.bodies,cls.before,cls.clone,cls.after=synthetic_catalog(TOOLS.parent,p)
    def reject(self,mutate):
        value=copy.deepcopy(self.catalog);mutate(value);self.assertRaises(ValueError,c.validate_catalog,value)
    def test_exact24_38_1131_1170(self):
        c.validate_catalog(self.catalog);self.assertEqual(len(c.PRIVATE_PROJECTS),38);self.assertEqual(len(c.AFFECTED_PROJECTS),24);self.assertEqual(self.catalog['original_count'],1131)
    def test_wrong_private_count(self):self.reject(lambda v:v.update(private_count=37))
    def test_bool_private_count(self):self.reject(lambda v:v.update(private_count=True))
    def test_extra_affected_role(self):self.reject(lambda v:v['affected_project_paths'].append('kernel/other'))
    def test_duplicate_transform(self):self.reject(lambda v:v['projects'][0]['files'].append(copy.deepcopy(v['projects'][0]['files'][0])))
    def test_escape_path(self):self.reject(lambda v:v['projects'][0]['files'][0].update(path='../outside'))
    def test_compiled_claim_rejected(self):self.reject(lambda v:v['pending_qualification'].update(compiled=True))
    def test_duplicate_json_member(self):self.assertRaises(ValueError,c.parse,b'{"schema":1,"schema":2}')
    def test_all80_exact_complete_replays(self):
        count=0
        for spec in self.catalog['projects']:
            for f in spec['files']:
                before=('synthetic before '+spec['path']+'/'+f['path']+'\n').encode();after=('synthetic after '+spec['path']+'/'+f['path']+'\n').encode()
                self.assertEqual(c.apply_exact(before,self.bodies[f['patch']['canonical_path']],f),after);count+=1
        self.assertEqual(count,80)
    def test_wrong_preimage(self):
        spec=self.catalog['projects'][0];f=spec['files'][0];self.assertRaises(ValueError,c.apply_exact,b'wrong',self.bodies[f['patch']['canonical_path']],f)
    def test_wrong_patch_fullbody(self):
        spec=self.catalog['projects'][0];f=spec['files'][0];a=('synthetic before '+spec['path']+'/'+f['path']+'\n').encode();self.assertRaises(ValueError,c.apply_exact,a,self.bodies[f['patch']['canonical_path']]+b'junk',f)
    def test_current_measured_producer_PIN_loads_exact_siblings(self):
        loaded=producer.bind('firstparty_current_provenance',TOOLS/'owner_source_provenance.py',producer.PROVENANCE_SHA,time.monotonic()+10)
        self.assertEqual(loaded.PRIVATE_COUNT,38);self.assertEqual(loaded.PROFILE,'owner-open-whole-control-v4');self.assertEqual(loaded._asb_catalog_helper(time.monotonic()+10).PRIVATE_PROJECTS,c.PRIVATE_PROJECTS)
    def test_unchanged_payload_drift_not_waived(self):
        spec=self.catalog['projects'][0];old=self.clone[spec['path']];new=copy.deepcopy(self.after[spec['path']]);next(r for r in new['source_files'] if r['path']=='fixture-ordinary')['sha256']='0'*64;self.assertRaises(ValueError,c.compare_fork,spec,old,new)
    def test_dangling_catalog_scoped_witness(self):
        raw=self.bodies[c.CATALOG_PATH];files=[file_row(p,n,b) for n,b in self.bodies.items()];control=inventory(p,files,'/synthetic/control');c.validate_control_catalog(self.catalog,raw,control)
        control['source_files']=[r for r in control['source_files'] if r['path']!=self.catalog['scoped_evidence'][0]['canonical_path']];self.assertRaises(ValueError,c.validate_control_catalog,self.catalog,raw,control)
    def test_scoped_witness_hash_mismatch(self):
        control=inventory(p,[file_row(p,n,b) for n,b in self.bodies.items()],'/synthetic/control');next(r for r in control['source_files'] if r['path']==self.catalog['scoped_evidence'][0]['canonical_path'])['sha256']='0'*64;self.assertRaises(ValueError,c.validate_control_catalog,self.catalog,self.bodies[c.CATALOG_PATH],control)

    def test_undeclared_extra_payload_not_waived(self):
        spec=self.catalog['projects'][0];new=copy.deepcopy(self.after[spec['path']]);new['source_files'].append(file_row(p,'unexpected',b'extra'));self.assertRaises(ValueError,c.compare_fork,spec,self.clone[spec['path']],new)

class CompleteNestedControls(unittest.TestCase):
    def setUp(self):self.graph=graph_fixture(1596,provenance=p)
    def evidence(self):
        g=self.graph;read=lambda d:p.parse(p.read_descriptor(d,time.monotonic()+20))
        receipt=read(g[13]['asb24_fullfork_receipt']);catalog=read(receipt['catalog_descriptor']);source4=c.validate_source4_baselines(read(receipt['source4_composition_descriptor']),read(receipt['source4_defensive_descriptor']),g[0]);return receipt,catalog,source4,read
    def validate(self,receipt=None,current=None):
        r,cat,s4,read=self.evidence();return c.validate_fork_receipt(receipt or r,self.graph[0],cat,read,read,current if current is not None else self.graph[2],s4)
    def test_current_full38_graph_and_all24_raw_nested_proofs(self):
        value=p.validate_graph(*self.graph);self.assertEqual(len(value['private_project_paths']),38);self.assertFalse(value['production_ready']);self.assertEqual(len(self.graph[3]['projects']),1131)
    def test_duplicate_receipt_project(self):
        r,_,_,_=self.evidence();r['projects'][1]=copy.deepcopy(r['projects'][0]);self.assertRaises(ValueError,self.validate,r)
    def test_historical_tuple(self):
        r,_,_,_=self.evidence();r['source_commit']='0'*40;self.assertRaises(ValueError,self.validate,r)
    def test_protected_metadata_changes(self):
        r,_,_,_=self.evidence();r['all_original_and_retained_metadata_after']['control']['root_fd9']=[2]*9;self.assertRaises(ValueError,self.validate,r)
    def test_alias_changes(self):
        r,_,_,_=self.evidence();r['projects'][0]['original_git_pointer_after']={'changed':True};self.assertRaises(ValueError,self.validate,r)
    def test_catalog_physical_path_changes(self):
        r,_,_,_=self.evidence();r['catalog_descriptor']['path']='/other/catalog';self.assertRaises(ValueError,self.validate,r)
    def test_source4_duplicate13_input(self):
        r,_,_,read=self.evidence();a=read(r['source4_composition_descriptor']);b=read(r['source4_defensive_descriptor']);a['projects'][-1]=copy.deepcopy(a['projects'][0]);self.assertRaises(ValueError,c.validate_source4_baselines,a,b,self.graph[0])
    def test_source4_writes_claim(self):
        r,_,_,read=self.evidence();a=read(r['source4_composition_descriptor']);b=read(r['source4_defensive_descriptor']);a['original_source_or_git_writes_performed']=True;self.assertRaises(ValueError,c.validate_source4_baselines,a,b,self.graph[0])
    def test_valid_other_current_generation_substitution(self):
        current=copy.deepcopy(self.graph[2]);current['art']=inventory(p,[file_row(p,'unrelated',b'other source')],'/synthetic/other');self.assertRaises(ValueError,self.validate,None,current)
    def test_unknown_surface_not_waived(self):
        r,cat,s4,read=self.evidence();target=r['projects'][0]['clone_surface_after']['path']
        def read_surface(d):
            value=read(d)
            if d['path']==target:value.update(accepted=False,unknown_entries=['undeclared'])
            return value
        self.assertRaises(ValueError,c.validate_fork_receipt,r,self.graph[0],cat,read,read_surface,self.graph[2],s4)
    def test_original_full_inventory_changes_not_waived(self):
        r,cat,s4,read=self.evidence();target=r['projects'][0]['original_after']['path']
        def read_inventory(d):
            value=read(d)
            if d['path']==target:value['source_files'][0]['sha256']='0'*64
            return value
        self.assertRaises(ValueError,c.validate_fork_receipt,r,self.graph[0],cat,read_inventory,read,self.graph[2],s4)
    def test_source4_wrong_complete_head_not_waived(self):
        r,cat,s4,read=self.evidence();s4['frameworks/base']=dict(s4['frameworks/base'],private_head='0'*40);self.assertRaises(ValueError,c.validate_fork_receipt,r,self.graph[0],cat,read,read,self.graph[2],s4)
    def test_legacy16_composition_not_upgraded_by_label(self):
        graph=copy.deepcopy(self.graph);graph[13].update(schema='org.trillionnium.audit.actual-exact-private-android-source-binding.v1',private_project_count=16);self.assertRaises(p.SourceError,p.validate_graph,*graph)

class RealCompleteCloneControls(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=pathlib.Path(self.temp.name);self.source=self.root/'source';self.source.mkdir(mode=0o700);self.evidence=self.root/'evidence';self.evidence.mkdir(mode=0o700);self.control=self.root/'control';self.control.mkdir(mode=0o700)
        self.env=dict(os.environ,GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GIT_AUTHOR_NAME='Fixture',GIT_AUTHOR_EMAIL='fixture@local.invalid',GIT_COMMITTER_NAME='Fixture',GIT_COMMITTER_EMAIL='fixture@local.invalid')
    def git(self,*args):
        result=subprocess.run(['/usr/bin/git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-C',str(self.source),*args],env=self.env,capture_output=True,timeout=20);self.assertEqual(result.returncode,0,result.stderr);return result.stdout
    def save(self,label,value):
        path=self.evidence/(label+'.json');path.write_bytes(p.canonical(value));return p.descriptor(path,path.read_bytes())
    def bound(self):
        head,tree=self.git('rev-parse','HEAD','HEAD^{tree}').decode().splitlines();return dict(root=str(self.source),root_fd9=producer.ident(self.source.lstat()),metadata_root=str(self.source/'.git'),head=head,tree=tree,git_pointer=producer.git_pointer(self.source,self.source/'.git',time.monotonic()+10))
    def test_full_clone_preserves_all_unmodified_rows_and_gitlink_reference(self):
        before=b'ordinary before\n';after=b'ordinary after\n';name='runtime/fixture.cc';f=dict(path=name,git_mode='100644',before=dict(bytes=len(before),sha256=c.digest(before),git_blob_sha1=c.blob(before)),after=dict(bytes=len(after),sha256=c.digest(after),git_blob_sha1=c.blob(after)),patch=dict(canonical_path='patch.diff',old_label='actual-captured/art/'+name,new_label='owned-final/art/'+name))
        import difflib
        patch=''.join(difflib.unified_diff(before.decode().splitlines(keepends=True),after.decode().splitlines(keepends=True),fromfile=f['patch']['old_label'],tofile=f['patch']['new_label'])).encode();f['patch'].update(bytes=len(patch),sha256=c.digest(patch));(self.control/'patch.diff').write_bytes(patch)
        (self.source/'runtime').mkdir();(self.source/name).write_bytes(before);(self.source/'ordinary').write_bytes(b'unchanged\n');(self.source/'executable').write_bytes(b'#!/bin/sh\n');(self.source/'executable').chmod(0o755);(self.source/'alias').symlink_to('ordinary');self.git('init','--quiet');self.git('add','.');self.git('update-index','--add','--cacheinfo','160000,'+'a'*40+',deps/sub');self.git('commit','--quiet','-m','Isolated complete source')
        bound=self.bound();spec=dict(path='art',historical_source_head=bound['head'],historical_source_tree=bound['tree'],baseline_kind='original_selected',files=[f]);result=producer._produce_project(spec,bound,self.root/'clone',p,c,surface,self.control,time.monotonic()+120,self.save,lambda _:None)
        inv={label:json.loads((self.evidence/(label+'.json')).read_bytes()) for label in ('original-before','original-after','clone-before','clone-after')};self.assertTrue(result['complete']);self.assertEqual(result['original_metadata_before'],result['original_metadata_after']);self.assertTrue(result['complete_git_objects']['no_hardlinks_or_alternates']);self.assertEqual(inv['original-before']['gitlinks'][0]['worktree_before']['state'],'missing');self.assertEqual(inv['clone-before']['gitlinks'][0]['worktree_before']['state'],'empty');c.clone_equivalent(inv['original-before'],inv['clone-before']);c.compare_fork(spec,inv['clone-before'],inv['clone-after'])
        wrong=copy.deepcopy(inv['clone-after']);wrong['gitlinks'][0]['git_commit']='b'*40;self.assertRaises(ValueError,c.compare_fork,spec,inv['clone-before'],wrong)
    def test_hydrated_original_disabled_smudge_clone_stays_HOLD(self):
        payload=b'hydrated fixture\n';pointer=('version https://git-lfs.github.com/spec/v1\noid sha256:'+hashlib.sha256(payload).hexdigest()+'\nsize '+str(len(payload))+'\n').encode();(self.source/'.gitattributes').write_bytes(b'payload.bin filter=lfs\n');(self.source/'payload.bin').write_bytes(pointer);self.git('init','--quiet');self.git('add','.');self.git('commit','--quiet','-m','LFS source');(self.source/'payload.bin').write_bytes(payload);bound=self.bound();inv=p.collect_git_checkout(self.source,bound['head'],bound['tree'],time.monotonic()+20,'external/libpng',120);self.assertIsNotNone(next(r for r in inv['source_files'] if r['path']=='payload.bin')['lfs'])
        with self.assertRaises(p.SourceError):producer._produce_project(dict(path='external/libpng',historical_source_head=bound['head'],historical_source_tree=bound['tree'],baseline_kind='original_selected',files=[]),bound,self.root/'unhydrated-clone',p,c,surface,self.control,time.monotonic()+60,self.save,lambda _:None)



class CurrentCanonicalCatalogControls(unittest.TestCase):
    """Real selected catalog bytes enter the unmodified production consumer.

    A deliberately incomplete receipt stops at the subsequent source4 guard.
    This checks catalog admission, never fabricates a completed fullfork.
    Fresh provenance namespaces keep synthetic fixture pins out of this gate.
    """
    def setUp(self):
        import types
        self.current=types.ModuleType('firstparty_current_catalog_pin')
        self.current.__file__=str(TOOLS/'owner_source_provenance.py')
        raw=(TOOLS/'owner_source_provenance.py').read_bytes()
        exec(compile(raw,self.current.__file__,'exec'),self.current.__dict__)
        self.raw=(TOOLS.parent/c.CATALOG_PATH).read_bytes()
        self.catalog=c.validate_catalog(c.parse(self.raw))
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=pathlib.Path(self.temp.name)
        self.control_root=self.root/'control';self.control_root.mkdir(mode=0o700)
        paths=[c.CATALOG_PATH]+[f['patch']['canonical_path'] for project in self.catalog['projects'] for f in project['files']]+[e['canonical_path'] for e in self.catalog['scoped_evidence']]
        rows=[]
        for name in paths:
            body=(TOOLS.parent/name).read_bytes()
            target=self.control_root/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(body)
            self.assertEqual(target.read_bytes(),body)
            rows.append(file_row(self.current,name,body))
        self.control={'source_files':rows}
        self.assertEqual(len(paths),83)

    def consumer(self,raw=None,receipt_sha=None):
        q=self.current
        catalog_path=self.control_root/c.CATALOG_PATH
        if raw is not None:
            catalog_path=self.root/'catalog.json';catalog_path.write_bytes(raw)
        body=catalog_path.read_bytes()
        receipt={'catalog_descriptor':q.descriptor(catalog_path,body),
                 'catalog_sha256':receipt_sha or q.sha(body),
                 'stage':str(self.root),
                 'scoped_evidence_descriptors':[q.descriptor(self.control_root/e['canonical_path'],(self.control_root/e['canonical_path']).read_bytes()) for e in self.catalog['scoped_evidence']]}
        path=self.root/'receipt.json';receipt_raw=q.canonical(receipt);path.write_bytes(receipt_raw)
        return q.validate_asb_fork_binding({'asb24_fullfork_receipt':q.descriptor(path,receipt_raw)},None,{'trillionnium-os':self.control},time.monotonic()+20)

    def test_fixed_provenance_catalog_PIN_equals_real_selected_bytes(self):
        self.assertEqual(self.current.ASB_CATALOG_SHA,hashlib.sha256(self.raw).hexdigest())

    def test_current_catalog_consumed_before_missing_source4_rejected(self):
        # No validator mock, no synthetic catalog pin, no success claim for
        # an incomplete receipt. A stale pin rejects before this exact guard.
        with self.assertRaisesRegex(KeyError,'source4_composition_descriptor'):
            self.consumer()

    def test_wrong_catalog_body_rejected_by_production_fixed_PIN(self):
        with self.assertRaisesRegex(self.current.SourceError,'current exact catalog source differs'):
            self.consumer(self.raw+b' ')

    def test_wrong_receipt_catalog_SHA_rejected_by_production_fixed_PIN(self):
        with self.assertRaisesRegex(self.current.SourceError,'current exact catalog source differs'):
            self.consumer(receipt_sha='0'*64)

    def test_all83_current_control_inputs_validate_without_substitution(self):
        self.assertTrue(c.validate_control_catalog(self.catalog,self.raw,self.control))
        wrong=copy.deepcopy(self.control)
        next(r for r in wrong['source_files'] if r['path']==self.catalog['scoped_evidence'][0]['canonical_path'])['sha256']='0'*64
        self.assertRaises(ValueError,c.validate_control_catalog,self.catalog,self.raw,wrong)

    def test_producer_META_vector_fixed_PIN_chain_loads_real_bodies(self):
        import types
        digest=lambda path:hashlib.sha256(path.read_bytes()).hexdigest()
        fixed=producer.bind('firstparty_S5_PIN_provenance',TOOLS/'owner_source_provenance.py',producer.PROVENANCE_SHA,time.monotonic()+10)
        self.assertEqual(fixed.ASB_CATALOG_SHA,hashlib.sha256(self.raw).hexdigest())
        self.assertEqual(producer.PROVENANCE_SHA,digest(TOOLS/'owner_source_provenance.py'))
        meta=types.ModuleType('firstparty_S5_PIN_META');meta.__file__=str(TOOLS/'verify_owner_target_files_binding.py')
        exec(compile((TOOLS/'verify_owner_target_files_binding.py').read_bytes(),meta.__file__,'exec'),meta.__dict__)
        self.assertEqual(meta.PROVENANCE_SOURCE_SHA,digest(TOOLS/'owner_source_provenance.py'))
        self.assertEqual(meta.p.ASB_CATALOG_SHA,hashlib.sha256(self.raw).hexdigest())
        vector=types.ModuleType('firstparty_S5_PIN_vector');vector.__file__=str(TOOLS/'collect_owner_source_vector.py')
        exec(compile((TOOLS/'collect_owner_source_vector.py').read_bytes(),vector.__file__,'exec'),vector.__dict__)
        loaded,_,_=vector.load_source()
        self.assertEqual(vector.SOURCE_SHA,digest(TOOLS/'owner_source_provenance.py'))
        self.assertEqual(vector.META_SHA,digest(TOOLS/'verify_owner_target_files_binding.py'))
        self.assertEqual(loaded.ASB_CATALOG_SHA,hashlib.sha256(self.raw).hexdigest())

if __name__=='__main__':unittest.main()
