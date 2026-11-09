#!/usr/bin/env python3
"""Retry fixed official transport and execute the original pinned extractor."""
import argparse
import hashlib
import json
from pathlib import Path
import ssl
import tempfile
import time
import types
import urllib.error
import urllib.parse
import urllib.request

URL = "https://github.com/qualcomm/GenieX/releases/download/v0.10.0/geniex-bench-android-arm64-v0.10.0.tar.gz"
ASSET_URL = "https://api.github.com/repos/qualcomm/GenieX/releases/assets/683271197"
BYTES = 98545327
SHA256 = "248b49c83bc74238babc0d9ebf46f0c8b6d2e9b6de3ffb90c2a5a2042523831f"
CORE_SHA256 = "99e2dbc8d95b08f8bb31b61b3c84219f4b70d6effeb38d224d54eeb621f28a56"
SOURCE_FETCH_SHA256 = "3fd70e3fbe4e5f617a2cbab08bd703dd4795137c9d9562936cf996a9fe77f05c"
ALLOWED_HOSTS = frozenset(("github.com", "api.github.com",
    "release-assets.githubusercontent.com", "objects.githubusercontent.com"))
RETRY_HTTP = frozenset((429, 500, 502, 503, 504))


class IntegrityError(RuntimeError):
    pass


class TransportError(RuntimeError):
    pass


def verify_helper_closure(root):
    records = json.loads((root / "HELPER-MANIFEST.json").read_text())["files"]
    if set(records) != {"fetch_verified_runtime.py", "test_fetch_verified_runtime.py",
                        "README.md", "PROVENANCE.json"}:
        raise IntegrityError("CI transport helper member set mismatch")
    for name, pin in records.items():
        data = (root / name).read_bytes()
        if len(data) != pin["bytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise IntegrityError("CI transport helper member mismatch: " + name)


def load_frozen_source(source):
    path = source / "tools" / "fetch_pinned_runtime.py"
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_FETCH_SHA256:
        raise IntegrityError("frozen runtime fetch source SHA256 mismatch")
    module = types.ModuleType("hepta_frozen_runtime_fetch")
    module.__file__ = str(path)
    exec(compile(data, str(path), "exec"), module.__dict__)
    expected = {"URL": URL, "BYTES": BYTES, "SHA256": SHA256, "CORE_SHA256": CORE_SHA256}
    if any(getattr(module, key, None) != value for key, value in expected.items()):
        raise IntegrityError("frozen runtime pin contract mismatch")
    return module


class VerifiedTransport:
    """Retry transport failures; never retry an archive integrity failure."""
    def __init__(self, expected_bytes=BYTES, expected_sha256=SHA256,
                 opener=None, sleeper=None):
        self.expected_bytes = expected_bytes
        self.expected_sha256 = expected_sha256
        self.opener = opener or urllib.request.urlopen
        self.sleeper = sleeper or time.sleep
        self.attempts = []
        self.selected_transport = None

    def _download(self, endpoint, timeout):
        headers = {"User-Agent": "hepta-fixed-runtime-ci/1",
                   "Accept-Encoding": "identity", "Cache-Control": "no-cache"}
        if endpoint == ASSET_URL:
            headers.update({"Accept": "application/octet-stream",
                            "X-GitHub-Api-Version": "2022-11-28"})
        request = urllib.request.Request(endpoint, headers=headers)
        result = tempfile.TemporaryFile(mode="w+b")
        try:
            with self.opener(request, timeout=min(timeout, 60)) as response:
                final = urllib.parse.urlparse(response.geturl())
                if final.scheme != "https" or final.hostname not in ALLOWED_HOSTS:
                    raise IntegrityError("runtime response left official HTTPS hosts")
                if response.status != 200:
                    raise TransportError("unexpected successful-response HTTP status")
                length = response.headers.get("Content-Length")
                if length is not None:
                    try:
                        length = int(length)
                    except ValueError as exc:
                        raise IntegrityError("invalid runtime Content-Length") from exc
                    if length != self.expected_bytes:
                        raise IntegrityError("runtime Content-Length differs from fixed size")
                size = 0
                checksum = hashlib.sha256()
                while True:
                    data = response.read(min(1024 * 1024, self.expected_bytes + 1 - size))
                    if not data:
                        break
                    size += len(data)
                    if size > self.expected_bytes:
                        raise IntegrityError("runtime exceeds fixed archive size")
                    result.write(data)
                    checksum.update(data)
                if size != self.expected_bytes or checksum.hexdigest() != self.expected_sha256:
                    raise IntegrityError("runtime size/SHA256 mismatch")
                result.seek(0)
                return result
        except BaseException:
            result.close()
            raise

    def __call__(self, url, timeout=60):
        if url != URL:
            raise IntegrityError("frozen extractor requested an unexpected URL")
        plan = (URL, URL, ASSET_URL, ASSET_URL)
        for index, endpoint in enumerate(plan):
            record = {"attempt": index + 1, "transport_url": endpoint}
            self.attempts.append(record)
            try:
                stream = self._download(endpoint, timeout)
            except urllib.error.HTTPError as exc:
                record.update(result="http_error", status=exc.code)
                if exc.code not in RETRY_HTTP:
                    raise TransportError("nonretryable official HTTP status " + str(exc.code)) from exc
            except urllib.error.URLError as exc:
                record.update(result="network_error", error_type=type(exc.reason).__name__)
                if isinstance(exc.reason, ssl.SSLCertVerificationError):
                    raise TransportError("TLS certificate verification failed") from exc
            except (TimeoutError, ConnectionError) as exc:
                record.update(result="network_error", error_type=type(exc).__name__)
            except IntegrityError:
                record.update(result="integrity_failure")
                raise
            else:
                record.update(result="verified", bytes=self.expected_bytes,
                              sha256=self.expected_sha256)
                self.selected_transport = endpoint
                return stream
            if index + 1 < len(plan):
                self.sleeper(2)
        raise TransportError("fixed official transport exhausted four bounded attempts")


def fetch_with_verified_transport(module, destination, transport):
    # Change only this isolated module's network response dependency.
    # The URL, archive/core pins, extractor, and on-disk source stay unchanged.
    original = module.urllib
    module.urllib = types.SimpleNamespace(request=types.SimpleNamespace(urlopen=transport))
    try:
        module.fetch(destination)
    finally:
        module.urllib = original


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args()
    if args.receipt.exists():
        raise FileExistsError("create-only transport receipt already exists")
    report = {"schema": "hepta.fixed-runtime-ci-transport.v1",
              "source_fetch_sha256": SOURCE_FETCH_SHA256,
              "official_url": URL, "fixed_asset_api_url": ASSET_URL,
              "archive_bytes": BYTES, "archive_sha256": SHA256,
              "core_library_sha256": CORE_SHA256, "maximum_attempts": 4,
              "phone_contacted": False, "models_downloaded": False,
              "source_modified": False, "original_extractor_and_pins_preserved": True}
    transport = VerifiedTransport()
    try:
        verify_helper_closure(Path(__file__).resolve().parent)
        module = load_frozen_source(args.source.resolve())
        fetch_with_verified_transport(module, args.destination, transport)
        report["result"] = "success"
    except Exception as exc:
        report.update(result="failure", error_type=type(exc).__name__,
                      error_message=str(exc)[:400])
        raise
    finally:
        report["attempts"] = transport.attempts
        report["selected_transport"] = transport.selected_transport
        args.receipt.parent.mkdir(parents=True, exist_ok=True)
        with args.receipt.open("x") as out:
            json.dump(report, out, indent=2)
            out.write("\n")


if __name__ == "__main__":
    main()
