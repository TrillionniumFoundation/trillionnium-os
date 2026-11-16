#!/usr/bin/env python3
"""Real profile/legacy quota methods; broker dispatch order is checked as source only."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source',type=Path,default=Path(__file__).resolve().parents[2])
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--java-home',type=Path,required=True)
    p.add_argument('--baseline-protocol',type=Path)
    a=p.parse_args()
    source,out=a.source.resolve(),a.output.resolve()
    out.mkdir(parents=True,exist_ok=False)
    package=source/'src/org/trillionnium/hepta/background'
    common=[package/(n+'.java') for n in ('ProfileIdentity','ProfileTarget','WindowOwnership','FixedIntentTools')]
    test=Path(__file__).with_name('ProfileQuotaHostTest.java')
    broker=package/'BackgroundDisplayBroker.java'
    text=broker.read_text()
    ordered='request.authenticate(config, accepted.getPeerCredentials().getUid());\n                    response = receipts.replay(request);'
    assert text.count(ordered)==1,'broker authentication/replay order changed'
    def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
    variants=[]
    selected=[('current',package/'BrokerProtocol.java',False)]
    if a.baseline_protocol:selected.insert(0,('baseline',a.baseline_protocol.resolve(),True))
    for name,protocol,expected_red in selected:
        dest=out/name;dest.mkdir()
        classes=dest/'classes';classes.mkdir()
        files=common+[protocol,test]
        pins={p.name:sha(p) for p in files}
        stages=[]
        for stage,argv in [
            ('compile',[a.java_home/'bin/javac','--release','8','-encoding','UTF-8','-proc:none','-Xlint:all,-options','-Werror','-d',classes,*files]),
            ('quota',[a.java_home/'bin/java','-cp',classes,'org.trillionnium.hepta.background.ProfileQuotaHostTest',dest/'CASES.json'])]:
            begun=time.monotonic()
            result=subprocess.run([str(x) for x in argv],capture_output=True,timeout=90,cwd=dest)
            (dest/(stage+'.stdout')).write_bytes(result.stdout)
            (dest/(stage+'.stderr')).write_bytes(result.stderr)
            stages.append(dict(name=stage,exit_code=result.returncode,elapsed_seconds=time.monotonic()-begun))
            if stage=='compile':assert result.returncode==0,result.stderr.decode(errors='replace')
        if expected_red:
            assert stages[1]['exit_code']!=0
            assert b'legacy_quota_completed' in result.stdout
            assert b'SESSION_REQUEST_LIMIT' in result.stderr and b'ProfileQuotaHostTest.filled' in result.stderr
            assert not (dest/'CASES.json').exists()
        else:
            assert stages[1]['exit_code']==0,result.stderr.decode(errors='replace')
        assert pins=={p.name:sha(p) for p in files}
        variants.append(dict(name=name,expected_baseline_failure=expected_red,stages=stages,source_inputs=pins,
                             cases=None if expected_red else json.loads((dest/'CASES.json').read_text())))
    report=dict(schema='hepta.profile-request-quota-validation.v1',all_pass=True,variants=variants,
                broker_authentication_before_replay_source_checked=True,broker_source_sha256=sha(broker),
                broker_android_io_executed=False,actual_receipts_and_authentication_executed=True,
                no_receipt_eviction=True,phone_actions=0)
    (out/'RESULT.json').write_text(json.dumps(report,ensure_ascii=False,indent=2,sort_keys=True)+'\n')
    print(json.dumps(dict(all_pass=True,variants=[dict(name=v['name'],cases=v['cases']) for v in variants])))
if __name__=='__main__':main()
