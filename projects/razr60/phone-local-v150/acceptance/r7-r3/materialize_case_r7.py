#!/usr/bin/env python3
"""Materialize fresh r7 bytes only. Requires a fully frozen combination; never registers/sends."""
import argparse,json,os,re,secrets
from pathlib import Path
import aggregate_protocol_r7 as binding
def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument("kind",choices=("health","visual","unicode"))
 p.add_argument("--combination",type=Path,required=True)
 p.add_argument("--combination-sha256",required=True)
 p.add_argument("--out",type=Path,required=True)
 p.add_argument("--nonce")
 p.add_argument("--text-file",type=Path)
 a=p.parse_args()
 protocol,protocol_sha,_=binding.validate_protocol()
 combo=binding.load_combination(a.combination,a.combination_sha256)
 binding.require(combo["frozen"],"No materialization against pending module/policy/native-App inputs")
 binding.require(a.kind=="unicode" or a.text_file is None,"text_file_only_for_unicode")
 old=binding.frozen_module("materialize_case_r4.py",binding.MATERIALIZER_SHA)
 # This overrides only the old metadata constant, not request text or postconditions.
 old.SEAL=binding.SOURCE_SHA
 nonce=a.nonce or secrets.token_hex(16)
 text=None
 if a.kind=="unicode":
  if a.text_file:
   text=old.snapshot(a.text_file).decode("utf-8",errors="strict")
  else:
   marker=secrets.token_hex(12)
   text=("本机验收·"+marker+" 🦉📱\n"
    "第二行：原样保留 \"双引号\" '单引号' 与 $HOME $(echo literal) ; & | < > "
    +chr(96)+"反引号"+chr(96)+" \\")
 raw,conditions,extras,meta=old.materialize(a.kind,nonce,text)
 binding.require(meta["candidate_source_seal_sha256"]==binding.SOURCE_SHA,"material_source_binding")
 output=a.out.absolute()
 binding.require(output.parent.is_dir() and output.parent.resolve()==output.parent,"new_output_parent")
 output.mkdir(mode=0o700)
 files=[binding.write_new(output/"request.txt",raw)]
 if conditions is not None:files.append(binding.write_new(output/"postconditions.json",old.json_bytes(conditions)))
 for name,data in extras.items():files.append(binding.write_new(output/name,data))
 combo_raw=binding.read(a.combination,32768)
 binding.require(binding.sha(combo_raw)==combo["manifest_sha256"],"combination_changed_before_capture")
 files.append(binding.write_new(output/"combination.json",combo_raw))
 meta.update(schema="hepta.fresh-acceptance-material.v150.r7.1",
  combination_sha256=combo["combination_sha256"],combination_manifest_sha256=combo["manifest_sha256"],
  service_inputs_sha256=binding.SERVICE_SHA,provider_config_sha256=binding.CONFIG_SHA,
  protocol_sha256=protocol_sha,original_protocol_sha256=binding.ORIGINAL_PROTOCOL_SHA,
  original_materializer_sha256=binding.MATERIALIZER_SHA,
  source_only_binding_forbidden=True,files=list(files))
 files.append(binding.write_new(output/"material.json",old.json_bytes(meta)))
 print(json.dumps({"state":"fresh_bytes_only_no_registration_no_send","case":meta["case"],
  "request_sha256":meta["request_sha256"],"combination_sha256":combo["combination_sha256"],
  "files":files,"phone_calls":0,"model_requests":0,"automatic_replay":False},ensure_ascii=False))
if __name__=="__main__":main()
