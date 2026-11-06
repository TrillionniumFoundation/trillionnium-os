#!/usr/bin/env python3
"""Reproduce the independent cleanup reader in a new local directory only."""
from pathlib import Path
import argparse,hashlib,json,os


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args()
    here=Path(__file__).resolve().parent;out=Path(a.output).resolve()
    if os.path.lexists(out):raise ValueError('fresh reproduction namespace required')
    base=(here/'reader_base.py').read_bytes();extension=(here/'reader_extension.py').read_bytes()
    raw=base+extension;compile(raw,'independent_cleanup_reader','exec')
    source=(here/'verify_bound02_cleanup_result_UNBOUND.py').read_bytes()
    if raw!=source:raise ValueError('full unbound source reproduction differs')
    manifest=json.loads((here.parent/'MANIFEST.json').read_bytes())
    frozen={k:manifest[v] for k,v in [('operation_label','actor_label'),('source','source'),
        ('request','request'),('targets','targets'),('authority','authority')]}
    before=b'FROZEN = None\n';after=('FROZEN = '+repr(frozen)+'\n').encode()
    if raw.count(before)!=1:raise ValueError('one exact binding slot')
    bound=raw.replace(before,after)
    if bound.replace(after,before)!=raw or bound!=(here/'verify_bound02_cleanup_result_BOUND.py').read_bytes():
        raise ValueError('full binding/inverse differs')
    out.mkdir(mode=0o700)
    pins={}
    for name,body in [('verify_bound02_cleanup_result_UNBOUND.py',raw),('verify_bound02_cleanup_result_BOUND.py',bound)]:
        fd=os.open(out/name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as f:f.write(body);f.flush();os.fsync(f.fileno())
        if (out/name).read_bytes()!=body:raise ValueError('full created source readback differs')
        pins[name]={'bytes':len(body),'sha256':hashlib.sha256(body).hexdigest()}
    print(json.dumps({'same_complete_sources':pins,'phone_or_result_access':False},sort_keys=True))


if __name__=='__main__':main()
