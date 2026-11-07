#!/usr/bin/env python3
"""Register one exact fresh no-device health request. Does not send or infer."""
import argparse
import json
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent/"source"))
from health_contracts import raw_private, register

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--state",type=Path,required=True)
    p.add_argument("--request-file",type=Path,required=True)
    p.add_argument("--session-id",required=True)
    p.add_argument("--profile-id",required=True)
    p.add_argument("--nonce",required=True)
    args=p.parse_args()
    raw=raw_private(args.request_file.absolute(),512*1024)
    receipt=register(args.state,raw.decode("utf-8",errors="strict"),
                     args.session_id,args.profile_id,args.nonce)
    print(json.dumps({"status":"registered_one_time_final_only_health",**receipt},
                     ensure_ascii=False,separators=(",",":")))

if __name__=="__main__": main()
