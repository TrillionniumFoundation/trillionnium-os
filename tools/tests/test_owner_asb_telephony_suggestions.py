"""Source-bound SQL regression for the declared TelephonyProvider transform.

Compile the complete newly declared Java helpers, then execute their SQL against
finite SQLite FTS3/live-parent fixtures. This is not a full Android compilation,
actual user/subscription API qualification or installed-CVE qualification.
"""
import hashlib
import json
import pathlib
import re
import shutil
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CATALOG = ROOT / "android-integration/security-patches/owner-asb-fork-catalog.v1.json"


def production_inputs():
    catalog = json.loads(CATALOG.read_bytes())
    project = next(p for p in catalog["projects"]
                   if p["path"] == "packages/providers/TelephonyProvider")
    assert len(project["files"]) == 1
    file = project["files"][0]
    patch = (ROOT / file["patch"]["canonical_path"]).read_bytes()
    assert len(patch) == file["patch"]["bytes"]
    assert hashlib.sha256(patch).hexdigest() == file["patch"]["sha256"]
    # Both complete helper bodies are introduced by this declared production patch.
    added = "\n".join(line[1:] for line in patch.decode().splitlines()
                      if line.startswith("+") and not line.startswith("+++"))
    witness = json.loads((ROOT / catalog["scoped_evidence"][0]["canonical_path"]).read_bytes())
    return catalog, patch.decode(), added, witness


def complete_method(added, return_type, name):
    start = added.index("    private static " + return_type + " " + name + "(")
    brace = added.index("{", start)
    depth = 0
    quoted = False
    escaped = False
    for i in range(brace, len(added)):
        char = added[i]
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
            continue
        if char == '"':
            quoted = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return added[start:i + 1]
    raise AssertionError("complete declared Java helper required")


class TelephonyDeclaredSourceTests(unittest.TestCase):
    def test_all80_single_telephony_transform_and_witness_are_bound(self):
        catalog, patch, added, witness = production_inputs()
        self.assertEqual(sum(len(p["files"]) for p in catalog["projects"]), 80)
        self.assertEqual(catalog["private_count"], 38)
        self.assertFalse(witness["correction"]["new_SQL_root_semantic_admission"])
        self.assertFalse(witness["correction"]["compiled_Android"])
        self.assertEqual(witness["source_bound_SQL_review"]["actual_FTS3_DDL"],
                         "CREATE VIRTUAL TABLE words USING FTS3 (_id INTEGER PRIMARY KEY, index_text TEXT, source_id INTEGER, table_to_use INTEGER, sub_id INTEGER);")

    def test_query_uses_live_parent_and_caller_visible_tables(self):
        _, _, added, _ = production_inputs()
        method = complete_method(added, "String", "getSearchSuggestionsQuery")
        self.assertNotIn("words.sub_id", method)
        self.assertIn("part.mid=", method)
        self.assertIn("part._id=words.source_id", method)
        self.assertIn("._id=words.source_id", method)
        self.assertIn("ORDER BY snippet LIMIT 50;", method)
        self.assertIn("index_text MATCH ?", method)
        self.assertIn("getSearchSuggestionsQuery(smsTable, pduTable,", added)
        self.assertIn("if (selectionBySubIds == null)", added)

    def test_request_arguments_have_no_shared_static_array(self):
        _, patch, added, _ = production_inputs()
        self.assertIn("-    private static final String[] SEARCH_STRING", patch)
        self.assertNotIn("SEARCH_STRING", added)
        method = complete_method(added, "String[]", "getSearchSuggestionArgs")
        self.assertIn("return new String[] { pattern + '*' };", method)
        self.assertIn('getSearchSuggestionArgs(uri.getQueryParameter("pattern"))', added)


@unittest.skipUnless(shutil.which("javac") and shutil.which("java"),
                     "JDK is required to compile the declared production SQL helpers")
class TelephonyJavaSQLTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _, _, added, witness = production_inputs()
        cls.temp = tempfile.TemporaryDirectory(prefix="telephony-suggestion-java-")
        cls.root = pathlib.Path(cls.temp.name)
        query = complete_method(added, "String", "getSearchSuggestionsQuery")
        args = complete_method(added, "String[]", "getSearchSuggestionArgs")
        harness = r'''
public final class SuggestionQueryHarness {
METHOD_QUERY
METHOD_ARGS
    public static void main(String[] arguments) throws Exception {
        if (arguments[0].equals("query")) {
            String selection = arguments[3].equals("NULL") ? null : arguments[3];
            System.out.print(getSearchSuggestionsQuery(arguments[1], arguments[2], selection));
        } else {
            String[] first = getSearchSuggestionArgs("first");
            String[] second = getSearchSuggestionArgs("second");
            if (first == second || !first[0].equals("first*") || !second[0].equals("second*")) {
                throw new AssertionError("shared arguments");
            }
            java.util.concurrent.ExecutorService executor =
                    java.util.concurrent.Executors.newFixedThreadPool(4);
            java.util.List<java.util.concurrent.Future<?>> futures = new java.util.ArrayList<>();
            for (int i = 0; i < 256; i++) {
                final String expected = "request" + i;
                futures.add(executor.submit(() -> {
                    String[] own = getSearchSuggestionArgs(expected);
                    Thread.yield();
                    if (!own[0].equals(expected + "*")) throw new AssertionError("pattern race");
                }));
            }
            for (java.util.concurrent.Future<?> future : futures) future.get();
            executor.shutdown();
            System.out.print("request arguments remain separate");
        }
    }
}
'''.replace("METHOD_QUERY", query).replace("METHOD_ARGS", args)
        path = cls.root / "SuggestionQueryHarness.java"
        path.write_text(harness)
        result = subprocess.run([shutil.which("javac"), "-d", str(cls.root), str(path)],
                                capture_output=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr.decode())
        cls.ddl = witness["source_bound_SQL_review"]["actual_FTS3_DDL"]
        cls.restricted = cls.java("query", "sms_restricted", "pdu_restricted", "sub_id IN ('1','-1')")
        cls.full = cls.java("query", "sms", "pdu", "sub_id IN ('1','-1')")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def java(cls, *arguments):
        result = subprocess.run([shutil.which("java"), "-cp", str(cls.root),
                                 "SuggestionQueryHarness", *arguments], capture_output=True, timeout=30)
        if result.returncode:
            raise AssertionError(result.stderr.decode())
        return result.stdout.decode()

    def database(self):
        db = sqlite3.connect(":memory:")
        self.addCleanup(db.close)
        db.execute(self.ddl)
        db.executescript('''
            CREATE TABLE sms (_id INTEGER PRIMARY KEY, sub_id INTEGER, type INTEGER);
            CREATE TABLE pdu (_id INTEGER PRIMARY KEY, sub_id INTEGER, msg_box INTEGER, m_type INTEGER);
            CREATE TABLE part (_id INTEGER PRIMARY KEY, mid INTEGER);
            CREATE VIEW sms_restricted AS SELECT * FROM sms WHERE type != 3;
            CREATE VIEW pdu_restricted AS SELECT * FROM pdu
                WHERE msg_box != 3 AND m_type IN (128,132);
        ''')
        # Numeric Android type constants are finite fixture assumptions, as in the
        # source-bound Root SQL review; this does not execute Android access APIs.
        db.executemany("INSERT INTO sms VALUES(?,?,?)", [(1,1,1),(2,2,1),(3,1,3)])
        db.executemany("INSERT INTO pdu VALUES(?,?,?,?)", [(11,1,1,132),(12,2,1,132),(13,1,1,130)])
        db.executemany("INSERT INTO part VALUES(?,?)", [(101,11),(102,12),(103,13)])
        db.executemany("INSERT INTO words VALUES(?,?,?,?,?)", [
            (1,"audit own_sms",1,1,-1), (2,"foreign sms",2,1,-1),
            (3,"draft sms",3,1,-1), (4,"audit own_mms",101,2,-1),
            (5,"foreign mms",102,2,-1), (6,"wap mms",103,2,-1)])
        return db

    def test_stale_FTS_subscription_cannot_admit_foreign_live_parent(self):
        db = self.database()
        old = "SELECT snippet(words, '', ' ', '', 1, 1) as snippet FROM words WHERE index_text MATCH ? AND sub_id IN (1,-1) ORDER BY snippet LIMIT 50;"
        self.assertEqual(len(db.execute(old, ("foreign*",)).fetchall()), 2)
        self.assertEqual(db.execute(self.restricted, ("foreign*",)).fetchall(), [])
        self.assertEqual(db.execute(self.full, ("foreign*",)).fetchall(), [])

    def test_restricted_view_hides_drafts_and_WAP(self):
        db = self.database()
        for pattern in ("draft*", "wap*"):
            self.assertEqual(db.execute(self.restricted, (pattern,)).fetchall(), [])
            self.assertEqual(len(db.execute(self.full, (pattern,)).fetchall()), 1)
        self.assertEqual(len(db.execute(self.restricted, ("audit*",)).fetchall()), 2)

    def test_orphan_deleted_and_reassociated_live_parents(self):
        db = self.database()
        db.execute("INSERT INTO words VALUES(7,'orphan text',999,1,-1)")
        self.assertEqual(db.execute(self.full, ("orphan*",)).fetchall(), [])
        db.execute("DELETE FROM sms WHERE _id=1")
        self.assertEqual(len(db.execute(self.full, ("audit*",)).fetchall()), 1)
        db.execute("UPDATE part SET mid=12 WHERE _id=101")
        self.assertEqual(db.execute(self.full, ("audit*",)).fetchall(), [])

    def test_live_subscription_not_index_subscription_and_invalid_type(self):
        db = self.database()
        db.execute("UPDATE words SET sub_id=2 WHERE _id IN(1,4)")
        self.assertEqual(len(db.execute(self.full, ("audit*",)).fetchall()), 2)
        db.execute("INSERT INTO words VALUES(7,'invalid text',1,3,-1)")
        self.assertEqual(db.execute(self.full, ("invalid*",)).fetchall(), [])
        db.execute("UPDATE sms SET sub_id=2 WHERE _id=1")
        self.assertEqual(len(db.execute(self.full, ("audit*",)).fetchall()), 1)

    def test_limit_order_and_bound_pattern(self):
        db = self.database()
        for i in range(20, 80):
            db.execute("INSERT INTO sms VALUES(?,1,1)", (i,))
            db.execute("INSERT INTO words VALUES(?,?,?,1,-1)", (i,"many " + str(i),i))
        rows = db.execute(self.full, ("many*",)).fetchall()
        self.assertEqual(len(rows), 50)
        self.assertEqual(rows, sorted(rows))
        # MATCH may interpret valid search operators; the bound parent predicate
        # still excludes foreign data even when a caller requests both terms.
        combined = db.execute(self.full, ("foreign OR audit",)).fetchall()
        self.assertEqual(combined, db.execute(self.full, ("audit*",)).fetchall())
        self.assertEqual(db.execute(self.full, ("foreign*",)).fetchall(), [])

    def test_null_empty_selection_rejected_and_concurrent_args_are_private(self):
        for selection in ("NULL", ""):
            result = subprocess.run([shutil.which("java"), "-cp", str(self.root),
                                     "SuggestionQueryHarness", "query", "sms", "pdu", selection],
                                    capture_output=True, timeout=30)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b"subscription selection is required", result.stderr)
        self.assertEqual(self.java("arguments"), "request arguments remain separate")


if __name__ == "__main__":
    unittest.main()
