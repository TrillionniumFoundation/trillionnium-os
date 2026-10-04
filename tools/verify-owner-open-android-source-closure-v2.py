#!/usr/bin/env python3
"""Correct package-block parsing for the owner-open Android source closure."""
from __future__ import annotations

import argparse
import hashlib
import os
import stat
import time
import types
import json
from pathlib import Path
import re
import sys

SCRIPT_DIR = Path(__file__).resolve().parent
BASE_PATH = SCRIPT_DIR / "verify-owner-open-android-source-closure.py"
def bind_helper(name,path,expected_sha,register=False):
 """Execute the exact measured source bytes; never consult a bytecode cache."""
 path=Path(path)
 if not path.is_absolute() or '..' in path.parts or '.' in path.parts:raise RuntimeError('absolute canonical helper path required')
 deadline=time.monotonic()+5
 def budget():
  if time.monotonic()>=deadline:raise RuntimeError('whole source helper binding deadline')
 def identity(s):return (s.st_dev,s.st_ino,s.st_mode,s.st_nlink,s.st_uid,s.st_gid,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
 parent=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
 fd=None
 registered_obj=None
 previous=None
 had_previous=False
 try:
  for part in path.parts[1:-1]:
   budget();next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
   os.close(parent);parent=next_fd
  before=os.stat(path.name,dir_fd=parent,follow_symlinks=False)
  if not stat.S_ISREG(before.st_mode) or before.st_nlink!=1 or not 0<before.st_size<=1024*1024:raise RuntimeError('single-link bounded ordinary helper source required')
  fd=os.open(path.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=parent)
  if identity(os.fstat(fd))!=identity(before):raise RuntimeError('helper FD differs from entry')
  pieces=[];count=0
  while True:
   budget();block=os.read(fd,min(65536,1024*1024-count+1))
   if not block:break
   count+=len(block)
   if count>before.st_size or count>1024*1024:raise RuntimeError('helper source byte bound')
   pieces.append(block)
  raw=b''.join(pieces)
  if count!=before.st_size or hashlib.sha256(raw).hexdigest()!=expected_sha:raise RuntimeError('exact helper source SHA mismatch')
  if identity(os.fstat(fd))!=identity(before) or identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=identity(before):raise RuntimeError('helper source changed before execution')
  budget();obj=types.ModuleType(name);obj.__file__=str(path)
  if register:
   previous=sys.modules.get(name);had_previous=name in sys.modules
   sys.modules[name]=obj;registered_obj=obj
  exec(compile(raw,str(path),'exec'),obj.__dict__)
  budget();os.lseek(fd,0,os.SEEK_SET);after_digest=hashlib.sha256();count=0
  while True:
   budget();block=os.read(fd,min(65536,1024*1024-count+1))
   if not block:break
   count+=len(block)
   if count>before.st_size or count>1024*1024:raise RuntimeError('helper source grew after execution')
   after_digest.update(block)
  if count!=before.st_size or after_digest.hexdigest()!=expected_sha or identity(os.fstat(fd))!=identity(before) or identity(os.stat(path.name,dir_fd=parent,follow_symlinks=False))!=identity(before):raise RuntimeError('helper source changed after execution')
  budget();return obj
 except BaseException:
  if registered_obj is not None and sys.modules.get(name) is registered_obj:
   if had_previous:sys.modules[name]=previous
   else:sys.modules.pop(name,None)
  raise
 finally:
  try:
   try:
    if fd is not None:os.close(fd)
   finally:os.close(parent)
  except BaseException:
   if registered_obj is not None and sys.modules.get(name) is registered_obj:
    if had_previous:sys.modules[name]=previous
    else:sys.modules.pop(name,None)
   raise

BASE_SHA256 = "003a8c6e6097d83e900b15429afb497dfbadb1171c76d2abfc7152b0d6671d17"
BASE = bind_helper("owner_open_android_source_closure_v1_base", BASE_PATH, BASE_SHA256, register=True)

PROFILE = BASE.PROFILE
GENERATED_FRAGMENT = BASE.GENERATED_FRAGMENT
ANDROID_ROOT = BASE.ANDROID_ROOT
COMMON_OWNER_OPEN = BASE.COMMON_OWNER_OPEN
SUPERVISOR_CONFIG = BASE.SUPERVISOR_CONFIG


def added_product_packages(product_text: str) -> set[str]:
    marker = "PRODUCT_PACKAGES +="
    start = product_text.find(marker)
    if start < 0:
        return set()
    result: set[str] = set()
    started = False
    for raw_line in product_text[start + len(marker) :].splitlines():
        line = raw_line.strip()
        if "#" in line:
            line = line.split("#", 1)[0].rstrip()
        if not line:
            if started:
                break
            continue
        started = True
        for token in line.replace("\\", " ").split():
            if re.fullmatch(r"[A-Za-z0-9_.+-]+", token):
                result.add(token)
    return result


_base_verify = BASE.verify
BASE.added_product_packages = added_product_packages


def verify(root: Path):
    return _base_verify(root)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--json", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    report = verify(args.root)
    if args.json:
        print(json.dumps(report.value(), ensure_ascii=False, sort_keys=True, indent=2))
    elif report.ok:
        for warning in report.warnings:
            print(f"WARNING: {warning}")
        print("PASS_OWNER_OPEN_ANDROID_SOURCE_CLOSURE_V2 compiled=false")
    else:
        for error in report.errors:
            print(f"ERROR: {error}", file=sys.stderr)
        for warning in report.warnings:
            print(f"WARNING: {warning}", file=sys.stderr)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
