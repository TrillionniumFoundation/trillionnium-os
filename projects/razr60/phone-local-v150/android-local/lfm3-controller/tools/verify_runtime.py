"""Verify each packaged cached library against the complete SHA-pinned release."""
import hashlib
import io
import os
from pathlib import Path, PurePosixPath
import stat
import tarfile

from fetch_pinned_runtime import BYTES, SHA256, PREFIX


def file_sha(path):
    digest=hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
    return digest.hexdigest()


def verify_runtime_archive(archive, lib_root, relative_paths):
    archive=Path(archive); lib_root=Path(lib_root)
    if archive.is_symlink() or not archive.is_file():
        raise RuntimeError("A complete SHA-pinned GenieX release archive is required; set GENIEX_ANDROID_ARCHIVE or use fetch_pinned_runtime.py")
    descriptor=os.open(archive,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(descriptor,"rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise RuntimeError("Runtime archive must be a regular file")
        snapshot=stream.read(BYTES+1)
    if len(snapshot)!=BYTES or hashlib.sha256(snapshot).hexdigest()!=SHA256:
        raise RuntimeError("Runtime archive size/SHA256 differs from the pinned release")
    wanted=set(relative_paths)
    if not wanted or any(PurePosixPath(name).is_absolute() or ".." in PurePosixPath(name).parts for name in wanted):
        raise RuntimeError("Invalid cached runtime membership")
    expected={}
    # Hashing and parsing consume these same bounded immutable compressed bytes.
    with tarfile.open(fileobj=io.BytesIO(snapshot),mode="r:gz") as bundle:
        for member in bundle:
            if not member.name.startswith(PREFIX): continue
            name=member.name[len(PREFIX):]
            if name not in wanted: continue
            if name in expected or not member.isfile() or not 0<member.size<=256*1024*1024:
                raise RuntimeError("Invalid or duplicate pinned runtime member: "+name)
            stream=bundle.extractfile(member)
            if stream is None: raise RuntimeError("Missing pinned runtime payload")
            digest=hashlib.sha256()
            with stream:
                for block in iter(lambda:stream.read(1024*1024),b""): digest.update(block)
            path=lib_root/name
            if path.is_symlink() or not path.is_file() or path.stat().st_size!=member.size or file_sha(path)!=digest.hexdigest():
                raise RuntimeError("Cached runtime library differs from the pinned release: "+name)
            expected[name]={"bytes":member.size,"sha256":digest.hexdigest()}
    if set(expected)!=wanted: raise RuntimeError("Cached libraries are absent from the pinned release: "+repr(sorted(wanted-set(expected))))
    return expected
