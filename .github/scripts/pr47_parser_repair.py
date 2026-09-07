#!/usr/bin/env python3
from pathlib import Path


def main() -> None:
    verifier = Path("tools/docs/verify_component_documentation.py")
    source = verifier.read_text(encoding="utf-8")
    start = source.index("def strip_inline_code(")
    end = source.index("\ndef indentation_columns(", start)
    replacement = '''def _find_exact_backtick_run(line: str, marker: str, start: int = 0) -> int:
    """Find a maximal backtick run whose length exactly matches marker."""
    cursor = start
    marker_length = len(marker)
    while cursor < len(line):
        candidate = line.find(marker, cursor)
        if candidate < 0:
            return -1
        run_start = candidate
        while run_start > 0 and line[run_start - 1] == "`":
            run_start -= 1
        run_end = candidate + marker_length
        while run_end < len(line) and line[run_end] == "`":
            run_end += 1
        if candidate == run_start and run_end - run_start == marker_length:
            return candidate
        cursor = run_end
    return -1


def strip_inline_code(line: str, open_marker: str | None) -> tuple[str, str | None]:
    """Hide inline code spans, retaining an exact marker across physical lines."""
    characters = list(line)
    cursor = 0
    marker = open_marker

    if marker is not None:
        close = _find_exact_backtick_run(line, marker)
        span_end = len(line) if close < 0 else close + len(marker)
        for index in range(span_end):
            characters[index] = " "
        if close < 0:
            return "".join(characters), marker
        cursor = span_end
        marker = None

    while cursor < len(line):
        if line[cursor] != "`":
            cursor += 1
            continue
        run_end = cursor
        while run_end < len(line) and line[run_end] == "`":
            run_end += 1
        marker = line[cursor:run_end]
        close = _find_exact_backtick_run(line, marker, run_end)
        span_end = len(line) if close < 0 else close + len(marker)
        for index in range(cursor, span_end):
            characters[index] = " "
        if close < 0:
            return "".join(characters), marker
        cursor = span_end
        marker = None
    return "".join(characters), None

'''
    verifier.write_text(source[:start] + replacement + source[end + 1 :], encoding="utf-8")

    tests = Path("tools/tests/test_owner_open_broker_component_documentation.py")
    test_source = tests.read_text(encoding="utf-8")
    anchor = '\n\nif __name__ == "__main__":\n    unittest.main()'
    if anchor not in test_source:
        raise SystemExit("test insertion anchor missing")
    additions = r'''

    def test_unequal_backtick_run_cannot_supply_module_contract_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            link = "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
            prose = path.read_text(encoding="utf-8").replace(link, "MOD-FIXTURE")
            prose += (
                "\nExample: `` alpha ``` beta ` "
                "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md) gamma ``\n"
            )
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
            ):
                VERIFY.verify(root)

    def test_multiline_unequal_backtick_run_cannot_supply_module_contract_link(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            link = "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)"
            prose = path.read_text(encoding="utf-8").replace(link, "MOD-FIXTURE")
            prose += (
                "\nExample: `` alpha\n"
                "middle ``` beta ` [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md) gamma\n"
                "``\n"
            )
            path.write_text(prose, encoding="utf-8")
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "README missing module contract link docs/modules/MOD-FIXTURE.md",
            ):
                VERIFY.verify(root)
'''
    tests.write_text(test_source.replace(anchor, additions + anchor), encoding="utf-8")


if __name__ == "__main__":
    main()
