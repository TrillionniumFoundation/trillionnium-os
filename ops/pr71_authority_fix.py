from pathlib import Path

verifier = Path('tools/docs/verify_repository_authority.py')
source = verifier.read_text(encoding='utf-8')

old = '''BARE_AUTHORITY_PATH_RE = re.compile(\n    r"(?<![A-Za-z0-9_.+/-])((?:(?:docs|governance|schemas|apps|crates|tools|packaging|"\n    r"android-integration|evidence|foundations|planned|platform|profile)/"\n    r"[A-Za-z0-9_.+@~/-]+|README\\.md|SECURITY\\.md|CONTRIBUTING\\.md)"\n    r"(?:#[A-Za-z0-9_.:+-]+)?)"\n)'''
new = '''BARE_AUTHORITY_PATH_RE = re.compile(\n    r"(?<![A-Za-z0-9_.+/-])((?:(?:\\.{1,2}/)+)?(?:(?:docs|governance|schemas|apps|crates|tools|packaging|"\n    r"android-integration|evidence|foundations|planned|platform|profile)/"\n    r"[A-Za-z0-9_.+@~/-]+|README\\.md|SECURITY\\.md|CONTRIBUTING\\.md|"\n    r"TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN\\.md)(?:#[A-Za-z0-9_.:+-]+)?)"\n)'''
if old not in source:
    raise SystemExit('bare authority regex subject drifted')
source = source.replace(old, new, 1)

old = '''AUTHORITY_DIRECTORY_ROOTS = frozenset({\n    "docs/machine",\n    "docs/modules",\n    "docs/generated",\n    "schemas",\n})\n\n\ndef _semantic_visible_text(paragraph: str) -> str:\n    """Normalize rendered prose for authority-phrase classification.\n\n    Link extraction still uses the original paragraph so target/source ranges are\n    unchanged.  Semantic matching, however, must treat ordinary Markdown line\n    wrapping, emphasis and character entities as the visible text a reviewer\n    reads.  HTML tags are removed rather than trusted as semantic separators.\n    """\n    value = html.unescape(paragraph)\n    value = re.sub(r"<[^>]*>", " ", value)\n    value = value.translate(str.maketrans("", "", "*_~[]"))\n    return re.sub(r"\\s+", " ", value).strip()\n\n\ndef _registered_authority(target: str, authority_targets: set[str]) -> bool:\n    # Directory landing pages are explicit navigation roots.  No descendant is\n    # trusted merely because it lives under one of these directories.\n    return target in authority_targets or target in AUTHORITY_DIRECTORY_ROOTS\n'''
new = '''def _semantic_visible_text(paragraph: str) -> str:\n    """Normalize rendered prose for authority-phrase classification.\n\n    Target extraction still uses the original paragraph. Semantic matching uses\n    rendered link labels rather than Markdown destinations so permitted link\n    syntax cannot split a visible authority phrase. HTML tags are removed while\n    visible text remains, entities are decoded, and whitespace/emphasis normalize.\n    """\n    value = html.unescape(paragraph)\n    value = INLINE_LINK_RE.sub(lambda match: match.group(1), value)\n    value = REFERENCE_LINK_RE.sub(lambda match: match.group(1), value)\n    value = BRACKET_RE.sub(lambda match: match.group(1), value)\n    value = re.sub(r"<[^>]*>", " ", value)\n    value = value.translate(str.maketrans("", "", "*_~"))\n    return re.sub(r"\\s+", " ", value).strip()\n\n\ndef _registered_authority(target: str, authority_targets: set[str]) -> bool:\n    # Authority is granted only to exact registered file identities. Directory\n    # roots remain ordinary navigation targets and never confer authority.\n    return target in authority_targets\n'''
if old not in source:
    raise SystemExit('semantic authority subject drifted')
source = source.replace(old, new, 1)

old = '''                if syntax == "bare authority path":\n                    resolved = resolve_bare_repository_target(\n                        root, normalized_target,\n                        f"{relative}: visible line {paragraph_line} {syntax}",\n                    )\n                else:\n                    resolved = resolve_markdown_target(\n                        root, path, normalized_target,\n                        f"{relative}: visible line {paragraph_line} {syntax}",\n                    )'''
new = '''                if syntax == "bare authority path" and not normalized_target.startswith(("./", "../")):\n                    resolved = resolve_bare_repository_target(\n                        root, normalized_target,\n                        f"{relative}: visible line {paragraph_line} {syntax}",\n                    )\n                else:\n                    resolved = resolve_markdown_target(\n                        root, path, normalized_target,\n                        f"{relative}: visible line {paragraph_line} {syntax}",\n                    )'''
if old not in source:
    raise SystemExit('bare resolver subject drifted')
source = source.replace(old, new, 1)
verifier.write_text(source, encoding='utf-8')

start = Path('docs/START_HERE.md')
start_source = start.read_text(encoding='utf-8')
start_source = start_source.replace('Machine truth root: [`machine/`](machine/)  ', 'Machine catalog navigation: [`machine/`](machine/)  ', 1)
old = 'The source of truth is split by concern across [`machine/`](machine/):\n'
new = 'Browse machine records under [`machine/`](machine/).\n\nThe exact registered files below are authoritative for their individual concerns:\n'
if old not in start_source:
    raise SystemExit('START_HERE truth paragraph drifted')
start_source = start_source.replace(old, new, 1)
start.write_text(start_source, encoding='utf-8')

tests = Path('tools/tests/test_repository_authority.py')
test_source = tests.read_text(encoding='utf-8')
marker = '    def test_active_profile_cannot_select_sealed_component(self) -> None:\n'
if marker not in test_source:
    raise SystemExit('test marker drifted')
additions = '''    def test_inline_link_label_participates_in_authority_phrase(self) -> None:\n        path = self.root / "README.md"\n        path.write_text(path.read_text() + "\\nCanonical [plan](README.md) governs this tree.\\n")\n        with self.assertRaisesRegex(VERIFY.VerificationError, "unregistered target"):\n            VERIFY.verify(self.root)\n\n    def test_reference_link_label_participates_in_authority_phrase(self) -> None:\n        path = self.root / "README.md"\n        path.write_text(path.read_text() + "\\nCanonical [plan][self] governs this tree.\\n\\n[self]: README.md\\n")\n        with self.assertRaisesRegex(VERIFY.VerificationError, "unregistered target"):\n            VERIFY.verify(self.root)\n\n    def test_shortcut_link_label_participates_in_authority_phrase(self) -> None:\n        path = self.root / "README.md"\n        path.write_text(path.read_text() + "\\nCanonical [plan] governs this tree.\\n\\n[plan]: README.md\\n")\n        with self.assertRaisesRegex(VERIFY.VerificationError, "unregistered target"):\n            VERIFY.verify(self.root)\n\n    def test_navigation_directory_is_not_authority_target(self) -> None:\n        path = self.root / "README.md"\n        path.write_text(path.read_text() + "\\nCanonical source is [machine docs](docs/machine/).\\n")\n        with self.assertRaisesRegex(VERIFY.VerificationError, "unregistered target"):\n            VERIFY.verify(self.root)\n\n    def test_navigation_directory_remains_valid_non_authority_link(self) -> None:\n        path = self.root / "README.md"\n        path.write_text(path.read_text() + "\\nNavigation: [machine docs](docs/machine/).\\n")\n        VERIFY.verify(self.root)\n\n    def test_source_relative_bare_authority_path_is_validated(self) -> None:\n        self.add_forbidden_document()\n        path = self.root / "docs/START_HERE.md"\n        path.write_text(path.read_text() + "\\nCanonical plan is ./TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md.\\n")\n        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):\n            VERIFY.verify(self.root)\n\n    def test_parent_relative_bare_authority_path_is_validated(self) -> None:\n        self.add_forbidden_document()\n        path = self.root / "docs/generated/CURRENT_STATE.md"\n        path.write_text(path.read_text() + "\\nCanonical plan is ../TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md.\\n")\n        with self.assertRaisesRegex(VERIFY.VerificationError, "forbidden authority path"):\n            VERIFY.verify(self.root)\n\n'''
test_source = test_source.replace(marker, additions + marker, 1)
tests.write_text(test_source, encoding='utf-8')
