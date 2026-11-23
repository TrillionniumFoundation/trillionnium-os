#!/usr/bin/env python3
"""Rebuild only the independently pinned VLM Android worker; no APK/sign/phone steps."""
from pathlib import Path
import argparse,hashlib,importlib.util,json
ROOT=Path(__file__).resolve().parents[1]

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--ndk',type=Path,required=True)
    p.add_argument('--sdk-libs',type=Path,required=True,help='GenieX lib directory containing llama_cpp/')
    p.add_argument('--output',type=Path,required=True)
    args=p.parse_args();source=ROOT/'native/vlm-worker'
    pins=json.loads((ROOT/'native/local-vlm-runtime-pins.json').read_text())
    if hashlib.sha256((source/'SOURCE.json').read_bytes()).hexdigest()!=pins['source_manifest_sha256']:
        raise RuntimeError('VLM source manifest changed; no build attempted')
    spec=importlib.util.spec_from_file_location('hepta_frozen_vlm_build',source/'tools/build_android.py')
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    module.build(source,args.ndk,args.sdk_libs/'llama_cpp',args.output)
    receipt=json.loads((args.output/'BUILD-RECEIPT.json').read_text());worker=receipt['worker']
    if worker['bytes']!=pins['worker']['bytes'] or worker['sha256']!=pins['worker']['sha256']:
        raise RuntimeError('Rebuilt VLM differs from frozen full artifact identity; do not assemble')
