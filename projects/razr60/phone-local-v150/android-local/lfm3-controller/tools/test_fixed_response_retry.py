import importlib.util
import io
import json
from pathlib import Path
import ssl
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("candidate", Path(__file__).with_name("fetch_pinned_runtime.py"))
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class Response(io.BytesIO):
    def getcode(self):
        return 200


def failure(status):
    return urllib.error.HTTPError(m.URL, status, "test response", {}, io.BytesIO(b"error page"))


class FixedResponseContracts(unittest.TestCase):
    def records(self, root):
        return [json.loads(p.read_text()) for p in sorted(root.glob("download-response-*.json"))]

    def test_first_success_uses_original_url_and_does_not_write_archive(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            response = Response(b"payload")
            with patch.object(m.urllib.request, "urlopen", return_value=response) as open_url, patch.object(m.time, "sleep") as sleep:
                with m._open_fixed_response(root) as actual:
                    self.assertEqual(actual.read(), b"payload")
            open_url.assert_called_once_with(m.URL, timeout=60)
            sleep.assert_not_called()
            self.assertFalse((root / "geniex-android-v0.10.0.tar.gz").exists())
            self.assertEqual(self.records(root)[0]["outcome"], "response_opened")
            self.assertFalse(self.records(root)[0]["archive_verified"])

    def test_two_transient_responses_then_success_are_bounded_and_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            first, second = failure(504), failure(503)
            with patch.object(m.urllib.request, "urlopen", side_effect=[first, second, Response(b"ok")]) as open_url, patch.object(m.time, "sleep") as sleep:
                with m._open_fixed_response(root) as actual:
                    self.assertEqual(actual.read(), b"ok")
            self.assertEqual(open_url.call_count, 3)
            self.assertEqual([call.args for call in sleep.call_args_list], [(2,), (4,)])
            self.assertTrue(first.closed and second.closed)
            self.assertEqual([row["outcome"] for row in self.records(root)], ["http_error", "http_error", "response_opened"])
            self.assertEqual([row["retry_admitted"] for row in self.records(root)], [True, True, False])

    def test_third_transient_error_is_final_and_no_fourth_request_occurs(self):
        with tempfile.TemporaryDirectory() as tmp:
            errors = [failure(504), failure(502), failure(500)]
            with patch.object(m.urllib.request, "urlopen", side_effect=errors) as open_url, patch.object(m.time, "sleep") as sleep:
                with self.assertRaises(urllib.error.HTTPError) as raised:
                    m._open_fixed_response(Path(tmp))
            self.assertIs(raised.exception, errors[2])
            self.assertEqual(open_url.call_count, 3)
            self.assertEqual(sleep.call_count, 2)
            self.assertTrue(all(error.closed for error in errors))
            self.assertFalse(self.records(Path(tmp))[-1]["retry_admitted"])

    def test_4xx_is_not_retried(self):
        for status in (400, 401, 403, 404, 408, 429):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                with patch.object(m.urllib.request, "urlopen", side_effect=failure(status)) as open_url, patch.object(m.time, "sleep") as sleep:
                    with self.assertRaises(urllib.error.HTTPError):
                        m._open_fixed_response(Path(tmp))
                self.assertEqual(open_url.call_count, 1)
                sleep.assert_not_called()
                self.assertFalse(self.records(Path(tmp))[0]["retry_admitted"])

    def test_certificate_and_other_open_errors_remain_fatal(self):
        errors = [
            urllib.error.URLError(ssl.SSLCertVerificationError("test certificate failure")),
            urllib.error.URLError(ConnectionResetError("test transport reset")),
            TimeoutError("test timeout"),
        ]
        for error in errors:
            with self.subTest(error=type(error).__name__), tempfile.TemporaryDirectory() as tmp:
                with patch.object(m.urllib.request, "urlopen", side_effect=error) as open_url, patch.object(m.time, "sleep") as sleep:
                    with self.assertRaises(type(error)):
                        m._open_fixed_response(Path(tmp))
                self.assertEqual(open_url.call_count, 1)
                sleep.assert_not_called()

    def test_response_success_never_bypasses_original_archive_identity_gate(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "new-download"
            with patch.object(m.urllib.request, "urlopen", side_effect=[failure(504), Response(b"wrong bytes")]) as open_url, patch.object(m.time, "sleep"):
                with self.assertRaisesRegex(RuntimeError, "size/SHA256 mismatch"):
                    m.fetch(root)
            self.assertEqual(open_url.call_count, 2)
            self.assertEqual((root / "geniex-android-v0.10.0.tar.gz").read_bytes(), b"wrong bytes")
            self.assertFalse((root / "lib").exists())
            self.assertFalse((root / "dependency-receipt.json").exists())

    def test_body_read_error_is_not_retried_or_extracted(self):
        class BrokenBody(Response):
            def read(self, size=-1):
                raise ConnectionResetError("test body failure")
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "new-download"
            with patch.object(m.urllib.request, "urlopen", return_value=BrokenBody()) as open_url, patch.object(m.time, "sleep") as sleep:
                with self.assertRaises(ConnectionResetError):
                    m.fetch(root)
            self.assertEqual(open_url.call_count, 1)
            sleep.assert_not_called()
            self.assertFalse((root / "lib").exists())
            self.assertFalse((root / "dependency-receipt.json").exists())


if __name__ == "__main__":
    unittest.main()

