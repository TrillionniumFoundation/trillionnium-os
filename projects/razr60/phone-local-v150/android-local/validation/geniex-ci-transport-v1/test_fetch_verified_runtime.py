import hashlib
import io
from pathlib import Path
import ssl
import tempfile
import types
import unittest
import urllib.error
import fetch_verified_runtime as runtime

PAYLOAD = b"fixed official fixture"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()


class Response(io.BytesIO):
    def __init__(self, payload=PAYLOAD, length=None, host="release-assets.githubusercontent.com"):
        super().__init__(payload)
        self.status = 200
        self.headers = {} if length is None else {"Content-Length": str(length)}
        self.url = "https://" + host + "/fixed"
    def geturl(self):
        return self.url


class FakeNetwork:
    def __init__(self, results):
        self.results = list(results)
        self.requests = []
    def __call__(self, request, timeout):
        self.requests.append((request, timeout))
        value = self.results.pop(0)
        if isinstance(value, BaseException):
            raise value
        return value


def http_error(code):
    return urllib.error.HTTPError(runtime.URL, code, "fixture", {}, None)


class FixedTransportTest(unittest.TestCase):
    def transport(self, results):
        network = FakeNetwork(results)
        waits = []
        transport = runtime.VerifiedTransport(
            len(PAYLOAD), DIGEST, opener=network, sleeper=waits.append)
        return transport, network, waits

    def test_exact_payload_is_rewound_and_verified(self):
        transport, network, waits = self.transport([Response(length=len(PAYLOAD))])
        with transport(runtime.URL) as stream:
            self.assertEqual(stream.read(), PAYLOAD)
        self.assertEqual(len(network.requests), 1)
        self.assertEqual(waits, [])
        self.assertEqual(transport.attempts[0]["result"], "verified")

    def test_primary_transient_failure_retries_original_url(self):
        transport, network, waits = self.transport([http_error(504), Response()])
        with transport(runtime.URL) as stream:
            self.assertEqual(stream.read(), PAYLOAD)
        self.assertEqual([x[0].full_url for x in network.requests], [runtime.URL] * 2)
        self.assertEqual(waits, [2])

    def test_fixed_asset_api_fallback_after_primary_failures(self):
        transport, network, waits = self.transport([http_error(504), TimeoutError(), Response()])
        with transport(runtime.URL) as stream:
            self.assertEqual(stream.read(), PAYLOAD)
        request = network.requests[-1][0]
        self.assertEqual(request.full_url, runtime.ASSET_URL)
        self.assertEqual(request.get_header("Accept"), "application/octet-stream")
        self.assertFalse(request.has_header("Authorization"))
        self.assertEqual(transport.selected_transport, runtime.ASSET_URL)

    def test_transport_exhaustion_is_bounded(self):
        transport, network, waits = self.transport([http_error(503) for _ in range(4)])
        with self.assertRaises(runtime.TransportError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 4)
        self.assertEqual(waits, [2, 2, 2])

    def test_nonretryable_http_failure_stops(self):
        transport, network, waits = self.transport([http_error(404)])
        with self.assertRaises(runtime.TransportError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 1)
        self.assertFalse(waits)

    def test_sha_mismatch_has_no_retry_or_fallback(self):
        transport, network, waits = self.transport([Response(b"x" * len(PAYLOAD))])
        with self.assertRaises(runtime.IntegrityError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 1)
        self.assertFalse(waits)

    def test_short_archive_fails_integrity(self):
        transport, network, waits = self.transport([Response(PAYLOAD[:-1])])
        with self.assertRaises(runtime.IntegrityError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 1)

    def test_oversize_stream_is_bounded(self):
        response = Response(PAYLOAD + b"extra")
        transport, network, waits = self.transport([response])
        with self.assertRaises(runtime.IntegrityError):
            transport(runtime.URL)
        self.assertTrue(response.closed)
        self.assertEqual(len(network.requests), 1)

    def test_wrong_content_length_stops_before_body(self):
        transport, network, waits = self.transport([Response(length=1234)])
        with self.assertRaises(runtime.IntegrityError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 1)

    def test_unofficial_redirect_is_rejected(self):
        transport, network, waits = self.transport([Response(host="example.invalid")])
        with self.assertRaises(runtime.IntegrityError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 1)

    def test_unexpected_source_url_never_reaches_network(self):
        transport, network, waits = self.transport([])
        with self.assertRaises(runtime.IntegrityError):
            transport("https://example.invalid/runtime")
        self.assertFalse(network.requests)

    def test_certificate_error_has_no_fallback(self):
        transport, network, waits = self.transport([
            urllib.error.URLError(ssl.SSLCertVerificationError("fixture"))])
        with self.assertRaises(runtime.TransportError):
            transport(runtime.URL)
        self.assertEqual(len(network.requests), 1)

    def test_delegate_keeps_original_url_and_restores_dependency(self):
        original = object()
        module = types.SimpleNamespace(urllib=original)
        seen = []
        transport, network, waits = self.transport([Response()])
        def fetch(destination):
            seen.append(destination)
            with module.urllib.request.urlopen(runtime.URL, timeout=60) as stream:
                seen.append(stream.read())
        module.fetch = fetch
        runtime.fetch_with_verified_transport(module, Path("fixture"), transport)
        self.assertIs(module.urllib, original)
        self.assertEqual(seen, [Path("fixture"), PAYLOAD])

    def test_changed_source_is_rejected_before_execution(self):
        with tempfile.TemporaryDirectory() as root:
            source = Path(root)
            (source / "tools").mkdir()
            (source / "tools/fetch_pinned_runtime.py").write_text(
                'raise AssertionError("must not execute")\n')
            with self.assertRaises(runtime.IntegrityError):
                runtime.load_frozen_source(source)

    def test_helper_closure(self):
        runtime.verify_helper_closure(Path(runtime.__file__).resolve().parent)


if __name__ == "__main__":
    unittest.main()
