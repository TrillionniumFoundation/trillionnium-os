#!/usr/bin/env python3
"""Render caller-supplied system/task text into the pinned Qwen3VL ChatML shape.

This does not invent an official MobiMind action schema. Supply the independently
reviewed model-specific system instructions, and archive those exact input files.
"""
import argparse
import hashlib
import json
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument("--system",type=Path,required=True)
p.add_argument("--task",type=Path,required=True)
p.add_argument("--output",type=Path,required=True)
a=p.parse_args()
system=a.system.read_text(encoding="utf-8")
task=a.task.read_text(encoding="utf-8")
for text in (system,task):
    if any(marker in text for marker in ("<|im_start|>","<|im_end|>","<img>","</img>","<audio>","</audio>","\x00")):
        raise SystemExit("input contains reserved role/media markers")
rendered=("<|im_start|>system\n"+system+"<|im_end|>\n"+
          "<|im_start|>user\n"+task+"\n<img>screen</img><|im_end|>\n"+
          "<|im_start|>assistant\n").encode()
with a.output.open("xb") as f:
    f.write(rendered)
print(json.dumps({"bytes":len(rendered),"sha256":hashlib.sha256(rendered).hexdigest(),
                  "system_sha256":hashlib.sha256(a.system.read_bytes()).hexdigest(),
                  "task_sha256":hashlib.sha256(a.task.read_bytes()).hexdigest()},sort_keys=True))
