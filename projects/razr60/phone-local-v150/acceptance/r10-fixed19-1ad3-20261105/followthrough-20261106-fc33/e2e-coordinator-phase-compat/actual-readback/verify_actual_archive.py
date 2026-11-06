#!/usr/bin/env python3
"""Verify complete actual host publication/readback; no effects or replays."""
import base64
import hashlib
import json
from pathlib import Path
import stat
import types
import zlib

HERE = Path(__file__).resolve().parent
PARENT = HERE.parent
REVIEW = PARENT.parent


def pin(raw):
    return dict(bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def enc(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode()


def save(path, raw):
    path.parent.mkdir(exist_ok=True)
    with path.open('xb') as stream:
        stream.write(raw)


def main():
    helper = REVIEW/'install-build-controller/verify_host_controller_originals.py'
    raw = helper.read_bytes()
    assert pin(raw) == {'bytes':16570,'sha256':'be2b96db92bb456a798c3f8be6c1425a81e3afeadf782940bd695cf4cb3c714a'}
    H = types.ModuleType('reviewed_actual_compat_controller_reader'); H.__file__=str(helper)
    exec(compile(raw,str(helper),'exec'),H.__dict__)
    publication = H.strict((PARENT/'ROOT-ACTUAL-PUBLICATION-CONTROLLER.original.json').read_bytes())
    job,status,streams = H.controller(publication,code=0,complete=True)
    assert job['id']=='1a1b278051c-fc05-7e23' and streams['stderr']==b''
    assert publication['request']==H.strict((PARENT/'REQUEST.json').read_bytes())
    published=H.strict(streams['stdout'])
    observer=H.strict((HERE/'READ-CONTROLLER.original.json').read_bytes())
    oj,os_,output=H.controller(observer,code=0,complete=True)
    assert oj['id']=='1a1b27b8628-fc05-7e38' and output['stderr']==b''
    assert observer['request']['stdin'].encode()==(HERE/'observe_compat_originals.py').read_bytes()
    transfer=H.strict(output['stdout']);decoder=zlib.decompressobj()
    raw=decoder.decompress(base64.b64decode(transfer['raw_zlib_base64'],validate=True),4*1024*1024+1)
    assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
    assert pin(raw)==transfer['uncompressed'] and transfer['all_observation_fds_closed'] is True
    observed=H.strict(raw)
    assert observed['state']=='COMPLETE_8_PUBLISHED_COORDINATOR_COMPAT_HOST_SOURCE_ORIGINALS_READ'
    assert observed['publication_job_id']==job['id'] and observed['file_count']==8
    assert observed['all_original_files_read_to_EOF'] is True
    assert observed['all_directory_and_file_full9_bookended'] is True
    assert type(observed['phone_calls']) is int and observed['phone_calls']==0
    assert observed['project_modules_executed']==observed['host_file_writes']==0
    assert len(observed['groups'])==1
    group=observed['groups'][0];files=group['files'];names=set();copied=[]
    assert len(files)==8 and group['terminal']==published['derivation']
    target=HERE/'actual';target.mkdir(mode=0o700)
    for row in files:
        name=row['relative_path'];body=row['text'].encode()
        assert name not in names and row['path']==group['root']+'/'+name
        assert row['eof'] is True and pin(body)=={k:row[k]for k in ('bytes','sha256')}
        m=row['metadata'];assert all(type(x) is int for x in m.values())
        assert stat.S_ISREG(m['st_mode']) and stat.S_IMODE(m['st_mode'])==0o600
        assert m['st_nlink']==1 and m['st_size']==len(body)
        assert (PARENT/'publication-preview'/name).read_bytes()==body
        names.add(name);p=target/name;p.parent.mkdir(exist_ok=True)
        save(p,body);copied.append(dict(original={k:row[k]for k in ('path','bytes','sha256','metadata')},local=str(p)))
    total=sum(row['bytes'] for row in files)
    assert total==group['file_bytes']==observed['file_bytes']
    for directory in group['directories']:
        rel=directory['relative_path'];expected={Path(name).name for name in names if str(Path(name).parent)==(rel or '.')}
        if not rel:expected|={'source','reference','originals','requests'}
        assert sorted(expected)==directory['names']
    source=(target/'source/run_fixed19_e2e_root_once.py').read_bytes()
    original=(target/'reference/PARENT-COORDINATOR.original.py').read_bytes()
    assert source.replace(b"   receipts.append({**result,'phase':phase})\n",b'   receipts.append(dict(phase=phase,**result))\n')==original
    save(HERE/'ORIGINAL-TRANSFER.stdout.json',output['stdout'])
    save(HERE/'PUBLISHED-COORDINATOR-ORIGINALS.json',raw)
    save(HERE/'COPY-MAP.json',enc(copied))
    report=dict(schema='hepta.fc33.e2e.compat-actual-archive.verification.v1',
        state='ACTUAL_EIGHT_PUBLISHED_HOST_SOURCE_ORIGINALS_VERIFIED',
        publication_job=job['id'],independent_read_job=oj['id'],file_count=8,file_bytes=total,
        source=pin(source),source_compat=pin((target/'SOURCE-COMPAT.json').read_bytes()),
        full_byte_inverse=True,all_full9_EOF_and_directory_membership_verified=True,
        all_actual_files_equal_reviewed_preview=True, phone_calls=0,registrations=0,native_sends=0,
        actual_BUILD=None,actual_READY=None,actual_E2E=None,fixed19_credit=0,
        source_controls_rerun_during_readback=False)
    save(HERE/'VERIFICATION.json',enc(report));print(json.dumps(report,sort_keys=True))


if __name__=='__main__':
    main()
