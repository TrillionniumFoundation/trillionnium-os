"""Byte-bound caller for the standalone converter; no broker integration yet.

The original bytes go unchanged to a hash-pinned held executable descriptor.
Successful output is bounded GBNF; any stderr, nonzero exit, or timeout fails.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import struct
import subprocess

MAX_BYTES = 65536
COMMIT = "19cce6919992fdffd92e0ac152caaf1e2b8f254e"
SUBSET = "hepta.mobile-schema-gbnf-subset.v1"

def static_elf_contract(raw):
    if len(raw) < 64 or raw[:6] != b"\x7fELF\x02\x01":
        raise ValueError("64-bit little-endian ELF required")
    header = struct.unpack_from("<HHIQQQIHHHHHH", raw, 16)
    kind, machine, phoff, phsize, phnum = header[0], header[1], header[4], header[8], header[9]
    expected_machine = {"x86_64": 62, "aarch64": 183, "arm64": 183}.get(os.uname().machine)
    if kind not in (2, 3) or machine != expected_machine or phsize != 56 or not 0 < phnum <= 128:
        raise ValueError("converter ELF architecture/header differs")
    if phoff + phsize * phnum > len(raw):
        raise ValueError("converter ELF headers truncated")
    for index in range(phnum):
        part = struct.unpack_from("<IIQQQQQQ", raw, phoff + index * phsize)
        if part[0] == 3:
            raise ValueError("converter needs PT_INTERP inside chroot")
        if part[0] == 2:
            offset, size = part[2], part[5]
            if offset + size > len(raw) or size % 16:
                raise ValueError("converter dynamic table differs")
            for where in range(offset, offset + size, 16):
                tag, _ = struct.unpack_from("<qQ", raw, where)
                if tag == 1:
                    raise ValueError("converter has DT_NEEDED")
                if tag == 0:
                    break
    return {"elf_machine": machine, "elf_type": kind, "pt_interp": False, "dt_needed": []}

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def strict_json(raw):
    def pairs(values):
        out = {}
        for key, value in values:
            if key in out:
                raise ValueError("duplicate JSON key")
            out[key] = value
        return out
    return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
        parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))

def convert_schema(original_bytes, *, executable, executable_sha256, timeout=3.0):
    if not 0 < timeout <= 3.0:
        raise ValueError("converter CPU deadline bound")
    if not isinstance(original_bytes, bytes) or not 0 < len(original_bytes) <= MAX_BYTES:
        raise ValueError("schema byte bound")
    original = strict_json(original_bytes)
    canonical = json.dumps(original, ensure_ascii=False, sort_keys=True,
                           separators=(",", ":"), allow_nan=False).encode()
    executable = Path(executable)
    if not executable.is_absolute() or executable.parent.resolve(strict=True) != executable.parent:
        raise ValueError("converter path must be canonical and absolute")
    fd = os.open(executable, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    process = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_mode & 0o022:
            raise ValueError("converter file identity/mode differs")
        if not 0 < before.st_size <= 8 * 1024 * 1024:
            raise ValueError("converter executable byte bound")
        raw = bytearray()
        while len(raw) < before.st_size:
            part = os.read(fd, min(65536, before.st_size - len(raw)))
            if not part:
                raise ValueError("short executable read")
            raw.extend(part)
        after = os.fstat(fd)
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(after, field) for field in identity):
            raise ValueError("converter changed while hashing")
        if sha(raw) != executable_sha256:
            raise ValueError("converter executable SHA differs")
        elf = static_elf_contract(raw)
        process = subprocess.Popen(["/proc/self/fd/%d" % fd], pass_fds=(fd,),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, env={"LANG": "C", "LC_ALL": "C"})
        try:
            output, error = process.communicate(original_bytes, timeout=timeout)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise ValueError("converter exceeded bounded CPU time")
        if process.returncode != 0 or error:
            raise ValueError("converter rejected schema; returncode=%d stderr_sha256=%s" %
                             (process.returncode, sha(error)))
        if not 0 < len(output) <= MAX_BYTES or b"\0" in output:
            raise ValueError("grammar byte bound")
        output.decode("utf-8", "strict")
        if b"root ::=" not in output:
            raise ValueError("root rule absent")
        return output, {"schema": "hepta.schema-gbnf-conversion.v1", "subset": SUBSET,
            "root_schema_kind": "mobile_use" if "oneOf" in original else "health_final_only",
            "original_schema_bytes": len(original_bytes), "original_schema_sha256": sha(original_bytes),
            "canonical_schema_sha256": sha(canonical), "grammar_bytes": len(output),
            "grammar_sha256": sha(output), "grammar_root": "root", "converter_sha256": executable_sha256,
            "upstream_commit": COMMIT, "input_sent_unchanged": True, "returncode": process.returncode,
            "stderr_empty": True, "child_waited": True, "model_loaded": False,
            "executable_elf": elf,
            "native_action_authorized": False, "production_receipt": False}
    finally:
        if process is not None and process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
        os.close(fd)

def read_private(path):
    path = Path(path)
    if not path.is_absolute() or path.parent.resolve(strict=True) != path.parent:
        raise ValueError("private input path differs")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() \
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1 \
                or not 0 < before.st_size <= MAX_BYTES:
            raise ValueError("private schema file differs")
        raw = os.read(fd, MAX_BYTES + 1)
        after, named = os.fstat(fd), path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        if len(raw) != before.st_size or any(getattr(before, key) != getattr(after, key)
                or getattr(before, key) != getattr(named, key) for key in fields):
            raise ValueError("schema changed while reading")
        return raw
    finally:
        os.close(fd)

def exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise ValueError("short artifact write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--schema-file", required=True, type=Path)
    ap.add_argument("--converter", required=True, type=Path)
    ap.add_argument("--converter-sha256", required=True)
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    raw = read_private(args.schema_file)
    grammar, report = convert_schema(raw, executable=args.converter,
                                    executable_sha256=args.converter_sha256)
    if not args.out.is_absolute() or args.out.parent.resolve(strict=True) != args.out.parent:
        raise ValueError("output directory must be canonical and absolute")
    args.out.mkdir(mode=0o700, exist_ok=False)
    if stat.S_IMODE(args.out.stat().st_mode) != 0o700:
        raise ValueError("private output directory mode differs")
    exclusive(args.out / "original-schema.json", raw)
    exclusive(args.out / "grammar.gbnf", grammar)
    exclusive(args.out / "CONVERSION.json", json.dumps(report, sort_keys=True, indent=2).encode() + b"\n")
    directory = os.open(args.out, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    print(json.dumps(report, sort_keys=True))

if __name__ == "__main__":
    main()
