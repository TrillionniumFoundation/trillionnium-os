#!/usr/bin/env python3
"""Fetch the fixed public GenieX build dependency; never contacts an Android device.

The host must permit GitHub release downloads. This is optional: existing cached
lib directories remain the preferred path on the user's build hosts.
"""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import shutil
import tarfile
import time
import urllib.error
import urllib.request

URL = "https://github.com/qualcomm/GenieX/releases/download/v0.10.0/geniex-bench-android-arm64-v0.10.0.tar.gz"
BYTES = 98545327
SHA256 = "248b49c83bc74238babc0d9ebf46f0c8b6d2e9b6de3ffb90c2a5a2042523831f"
PREFIX = "geniex-bench-android-arm64-v0.10.0/lib/"
CORE_SHA256 = "99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56"

# Retry only a transient HTTP response before any archive is opened or written.
# A stream failure, size/SHA mismatch, 4xx response or TLS failure remains fatal.
TRANSIENT_HTTP_STATUS = frozenset((500, 502, 503, 504))
MAX_RESPONSE_ATTEMPTS = 3


def _open_fixed_response(destination):
    for attempt in range(1, MAX_RESPONSE_ATTEMPTS + 1):
        started = time.time()
        record = {"schema": "hepta.runtime-download-response.v1", "url": URL,
                  "attempt": attempt, "maximum_attempts": MAX_RESPONSE_ATTEMPTS,
                  "timeout_seconds": 60, "started_wall_s": started,
                  "archive_opened": False, "archive_verified": False,
                  "tls_verification_disabled": False}
        target = destination / ("download-response-%02d.json" % attempt)
        try:
            response = urllib.request.urlopen(URL, timeout=60)
        except urllib.error.HTTPError as error:
            retry = error.code in TRANSIENT_HTTP_STATUS and attempt < MAX_RESPONSE_ATTEMPTS
            record.update(outcome="http_error", http_status=error.code,
                          retry_admitted=retry, error_type=type(error).__name__)
            with target.open("x") as report:
                json.dump(record, report, indent=2); report.write("\n")
            error.close()
            if not retry:
                raise
            time.sleep(2 * attempt)
        except Exception as error:
            record.update(outcome="open_failed", retry_admitted=False,
                          error_type=type(error).__name__)
            with target.open("x") as report:
                json.dump(record, report, indent=2); report.write("\n")
            raise
        else:
            record.update(outcome="response_opened", http_status=response.getcode(),
                          retry_admitted=False)
            try:
                with target.open("x") as report:
                    json.dump(record, report, indent=2); report.write("\n")
            except BaseException:
                response.close()
                raise
            return response
    raise RuntimeError("fixed response attempts exhausted")


def fetch(destination):
    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=False)
    archive = destination / "geniex-android-v0.10.0.tar.gz"
    size = 0; checksum = hashlib.sha256()
    with _open_fixed_response(destination) as response, archive.open("xb") as out:
        while True:
            data = response.read(min(1024 * 1024, BYTES + 1 - size))
            if not data: break
            size += len(data)
            if size > BYTES: raise RuntimeError("release download exceeds pinned size")
            checksum.update(data); out.write(data)
    if size != BYTES or checksum.hexdigest() != SHA256:
        raise RuntimeError("release download size/SHA256 mismatch; no libraries extracted")
    files = []; total = 0
    with tarfile.open(archive, "r:gz") as tar:
        for member in tar:
            if not member.name.startswith(PREFIX) or member.isdir(): continue
            relative = PurePosixPath(member.name[len(PREFIX):])
            if relative.is_absolute() or ".." in relative.parts or not member.isfile():
                raise RuntimeError("runtime archive contains an unsupported library entry")
            if not (str(relative) == "libgeniex.so" or str(relative).startswith("llama_cpp/")): continue
            if relative.suffix != ".so": continue
            total += member.size
            if member.size > 256*1024*1024 or total > 512*1024*1024 or len(files) >= 128:
                raise RuntimeError("runtime libraries exceed extraction bounds")
            target = destination / "lib" / str(relative)
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None: raise RuntimeError("missing runtime library payload")
            with source, target.open("xb") as out: shutil.copyfileobj(source, out, 1024*1024)
            target.chmod(0o755)
            files.append({"path": str(target.relative_to(destination)), "bytes": target.stat().st_size,
                          "sha256": hashlib.sha256(target.read_bytes()).hexdigest()})
    core = destination/"lib/libgeniex.so"
    if not core.is_file() or hashlib.sha256(core.read_bytes()).hexdigest() != CORE_SHA256:
        raise RuntimeError("extracted libgeniex does not match the frozen Android build")
    receipt = {"schema": "hepta.runtime-dependency.v1", "version": "0.10.0", "url": URL,
               "archive_bytes": size, "archive_sha256": SHA256, "libraries": files,
               "phone_contacted": False, "models_downloaded": False}
    (destination/"dependency-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    print(str(destination/"lib"))


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--destination", type=Path, required=True)
    fetch(parser.parse_args().destination)

