"""Keep source-only rendering repairs distinct from original qualification bytes."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
PROJECT = ROOT / "projects/razr60/phone-local-v150"
ORIGINALS = {
    "model/provenance/official-model-card.raw.txt":
        "8520a786d7a9d411e45466c2b7e7786d062ec03f2778acecc4a45991a803d8d8",
    "provider/r6/README.raw.txt":
        "e82cdafb1c09d3b6b931f61330e277c93340dc017407ea9263f3dc6356277f6f",
    "qualification/history/PUBLIC-SOURCE-BOUNDARY-as-published-7645e697.raw.txt":
        "3d066fd61117b9939709ac8d4e8ccc1a772dd8d83b27d74f206ff3ea9e114004",
    "qualification/history/README-as-published-4f7f0886.raw.txt":
        "8ad63b09f70c2bced7df19a4768e0e15a5a4be858ca89e494d1a14d480d58cda",
    "qualification/history/README-as-published-7645e697.raw.txt":
        "b9d3a023ce087a480155ffb673679485de235fc1e3388c82204bb6906fd396ae",
    "qualification/history/README-as-published-86c0424.raw.txt":
        "df50da968fc420917986162aeeab099a1651a3a30e6da466f9b30a857fec5ff7",
}


class Razr60PublicationDocumentationTest(unittest.TestCase):
    def test_original_bytes_and_third_party_license_are_preserved(self) -> None:
        expected = dict(ORIGINALS)
        expected["executor/r4/vendor/hash/rotate-bits/LICENSE.md"] = (
            "ca0b44aec101afb6b46f4c39b23369fa06a64fb9c0add37c2689d702156fee55"
        )
        for path, digest in expected.items():
            with self.subTest(path=path):
                self.assertEqual(hashlib.sha256((PROJECT / path).read_bytes()).hexdigest(), digest)

    def test_display_changes_are_limited_to_declared_rendering_repairs(self) -> None:
        manifest = json.loads((PROJECT / "PUBLISH-MANIFEST.json").read_text())
        update = manifest["source_documentation_update"]
        self.assertFalse(update["runtime_sources_modified"])
        self.assertEqual(update["new_phone_or_model_requests"], 0)
        self.assertEqual({item["retained_raw_path"] for item in update["changes"]}, set(ORIGINALS))
        for item in update["changes"]:
            with self.subTest(path=item["display_path"]):
                original = (PROJECT / item["retained_raw_path"]).read_bytes()
                header, separator, displayed = (PROJECT / item["display_path"]).read_bytes().partition(b"\n\n")
                self.assertEqual(separator, b"\n\n")
                self.assertTrue(header.startswith(b"> Rendering note (2026-11-04):"))
                self.assertIn(Path(item["retained_raw_path"]).name.encode(), header)
                rule = item["rule"]
                if rule == "close_bibtex_fence":
                    expected = original + b"\n```\n"
                elif rule == "mark_required_placeholder_as_code":
                    token = b"<INSTANCE_BINDING_SHA256_REQUIRED>"
                    self.assertEqual(original.count(token), 1)
                    expected = original.replace(token, b"`" + token + b"`")
                else:
                    self.assertEqual(rule, "rebase_root_relative_navigation_after_historical_relocation")
                    expected = original
                    for source, target in item["link_rewrites"].items():
                        self.assertIn(("](" + source + ")").encode(), expected)
                        expected = expected.replace(("](" + source + ")").encode(), ("](" + target + ")").encode())
                        self.assertTrue(((PROJECT / item["display_path"]).parent / target).exists())
                self.assertEqual(displayed, expected)

    def test_current_publication_and_projection_entries_match_content(self) -> None:
        for name in ("PUBLISH-MANIFEST.json", "PUBLIC-PROJECTION-INDEX.json"):
            with self.subTest(manifest=name):
                manifest = json.loads((PROJECT / name).read_text())
                entries = manifest["files"]
                paths = [entry["path"] for entry in entries]
                self.assertEqual(paths, sorted(set(paths)))
                for entry in entries:
                    with self.subTest(path=entry["path"]):
                        data = (PROJECT / entry["path"]).read_bytes()
                        self.assertEqual(entry["bytes"], len(data))
                        self.assertEqual(entry["sha256"], hashlib.sha256(data).hexdigest())
                        blob = b"blob " + str(len(data)).encode() + b"\0" + data
                        self.assertEqual(entry["git_blob_sha"], hashlib.sha1(blob).hexdigest())
                if name == "PUBLIC-PROJECTION-INDEX.json":
                    exact = sum(entry["exact_original_bytes"] is True for entry in entries)
                    self.assertEqual(manifest["exact_files"], exact)
                    self.assertEqual(manifest["projected_or_generated_files"], len(entries) - exact)


if __name__ == "__main__":
    unittest.main()
