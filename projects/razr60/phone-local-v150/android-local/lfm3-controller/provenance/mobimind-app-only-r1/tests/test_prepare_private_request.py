import importlib.util,json,os,struct,tempfile,unittest,zlib
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('prepare_private_mobi',ROOT/'tools/prepare_private_request.py')
prepare=importlib.util.module_from_spec(spec);spec.loader.exec_module(prepare)

class PrivateRequestTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.root=Path(self.temp.name);self.fixture=self.root/'fixture';self.fixture.mkdir()
        source=json.loads((ROOT/'assets/official-gui-prompts.json').read_text());owner='打开设置进入应用页';history='(No history)'
        prompt=(source['builtin_prefix'].replace('{task}',owner)+source['builtin_variable'].replace('{history}',history).replace('<image_placeholder>','<img>screen</img>')).encode()
        chunk=lambda name,data:struct.pack('>I',len(data))+name+data+struct.pack('>I',zlib.crc32(name+data)&0xffffffff)
        image=b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR',struct.pack('>IIBBBBB',32,32,8,2,0,0,0))+chunk(b'IDAT',zlib.compress((b'\0'+b'\xff\xff\xff'*32)*32))+chunk(b'IEND',b'')
        self.image=self.root/'screen.png';self.image.write_bytes(image);(self.fixture/'prompt.txt').write_bytes(prompt)
        f={k:source[k] for k in ('source_repository','source_commit','source_path','source_git_blob')}
        f.update(schema='hepta.mobimind.private-gui-fixture.v1',prefix_sha256=prepare.PREFIX_SHA,variable_sha256=prepare.VARIABLE_SHA,
            task_utf8=owner,task_sha256=prepare.sha(owner.encode()),history_utf8=history,history_sha256=prepare.sha(history.encode()),prompt_sha256=prepare.sha(prompt),prompt_bytes=len(prompt),
            image_sha256=prepare.sha(image),image_bytes=len(image),image_width=32,image_height=32,template_wrapping=False,actions_executed=False,one_shot_concatenation=True)
        (self.fixture/'fixture.json').write_text(json.dumps(f,ensure_ascii=False))
    def tearDown(self):self.temp.cleanup()
    def test_private_staging_binding_and_no_replacement(self):
        out=self.root/'stage';r=prepare.prepare(self.fixture,self.image,out)
        self.assertFalse(r['phone_contacted']);self.assertFalse(r['actions_executed']);self.assertFalse(r['model_assets_included'])
        request=json.loads((out/'files/mobi-probe-request.json').read_text());self.assertEqual(prepare.sha(request['nonce'].encode()),r['nonce_sha256']);self.assertEqual(len(request['nonce']),64)
        self.assertEqual(request['request_id'],r['request_id']);self.assertEqual(request['expires_wall_ms']-request['created_wall_ms'],600000)
        for row in r['files']:
            path=out/row['path'];self.assertEqual(prepare.sha(path.read_bytes()),row['sha256']);self.assertEqual(path.stat().st_mode&0o777,0o600)
        with self.assertRaises(FileExistsError):prepare.prepare(self.fixture,self.image,out)
    def test_tampered_prompt_and_image_rejected_before_staging(self):
        for name,path in (('prompt',self.fixture/'prompt.txt'),('image',self.image)):
            original=path.read_bytes();path.write_bytes(original+b' ')
            with self.assertRaises(ValueError):prepare.prepare(self.fixture,self.image,self.root/('bad-'+name))
            self.assertFalse((self.root/('bad-'+name)).exists());path.write_bytes(original)
    def test_fixture_cannot_change_owner_or_type(self):
        p=self.fixture/'fixture.json';f=json.loads(p.read_text());f['task_utf8']='删除所有记录';p.write_text(json.dumps(f))
        with self.assertRaises(ValueError):prepare.prepare(self.fixture,self.image,self.root/'bad-owner')
    def test_links_and_invalid_budgets_rejected(self):
        link=self.root/'linked.png';link.symlink_to(self.image)
        with self.assertRaises(OSError):prepare.prepare(self.fixture,link,self.root/'bad-link')
        for deadline,tokens in ((999,256),(600001,256),(120000,513),(True,256)):
            with self.assertRaises(ValueError):prepare.prepare(self.fixture,self.image,self.root/'bad-budget',deadline,tokens)
        with self.assertRaises(ValueError):prepare.obj(b'{"x":1,"x":2}')

if __name__=='__main__':unittest.main()
