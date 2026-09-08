from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from tools.tests.test_owner_open_broker_component_documentation_html import (
    ComponentDocumentationHtmlBlockTests,
    VERIFY,
)


class ComponentDocumentationListContinuationHtmlTests(unittest.TestCase):
    def write_fixture(self, root: Path) -> None:
        helper = ComponentDocumentationHtmlBlockTests(methodName="runTest")
        helper.write_fixture(root)

    def replace_contract(self, root: Path, replacement: str) -> None:
        path = root / "active/README.md"
        prose = path.read_text(encoding="utf-8").replace(
            "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)",
            "MOD-FIXTURE",
        )
        path.write_text(prose + "\n" + replacement + "\n", encoding="utf-8")

    def replace_required_surfaces(self, root: Path, replacement: str) -> None:
        path = root / "active/README.md"
        prose = path.read_text(encoding="utf-8")
        prose = prose.replace(
            "[MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)",
            "MOD-FIXTURE",
        )
        prose = prose.replace(
            "```sh\n"
            "cargo test --locked -p active-package --all-targets\n"
            "```",
            "cargo test",
        )
        path.write_text(prose + "\n" + replacement + "\n", encoding="utf-8")

    def replace_required_command(self, root: Path, replacement: str) -> None:
        path = root / "active/README.md"
        prose = path.read_text(encoding="utf-8").replace(
            "```sh\n"
            "cargo test --locked -p active-package --all-targets\n"
            "```",
            replacement,
        )
        path.write_text(prose, encoding="utf-8")

    def assert_raw_html_rejected(self, replacement: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_contract(root, replacement)
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "raw HTML block opener is forbidden",
            ):
                VERIFY.verify(root)

    def assert_container_fence_rejected(self, replacement: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_required_surfaces(root, replacement)
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "container-nested fenced code block is forbidden",
            ):
                VERIFY.verify(root)

    def assert_invalid_backtick_info_rejected(self, replacement: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_required_command(root, replacement)
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "backtick fenced-code info string contains a backtick",
            ):
                VERIFY.verify(root)

    def test_unordered_list_continuation_html_cannot_supply_link(self) -> None:
        self.assert_raw_html_rejected(
            "- component details\n"
            "    <div>\n"
            "  [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            "    </div>"
        )

    def test_ordered_list_continuation_html_cannot_supply_link(self) -> None:
        self.assert_raw_html_rejected(
            "1. component details\n"
            "    <component-contract>\n"
            "   [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            "    </component-contract>"
        )

    def test_nested_blockquote_list_continuation_html_is_rejected(self) -> None:
        self.assert_raw_html_rejected(
            "> - component details\n"
            ">     <div>\n"
            ">   [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            ">     </div>"
        )

    def test_blockquote_fenced_example_cannot_supply_required_surfaces(self) -> None:
        self.assert_container_fence_rejected(
            "> ```sh\n"
            "> cargo test --locked -p active-package --all-targets\n"
            "> [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            "> ```"
        )

    def test_list_fenced_example_cannot_supply_required_surfaces(self) -> None:
        self.assert_container_fence_rejected(
            "- ```sh\n"
            "  cargo test --locked -p active-package --all-targets\n"
            "  [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)\n"
            "  ```"
        )

    def test_backtick_in_three_tick_fence_info_cannot_supply_command(self) -> None:
        self.assert_invalid_backtick_info_rejected(
            "```sh `\n"
            "cargo test --locked -p active-package --all-targets\n"
            "```"
        )

    def test_backtick_in_long_fence_info_with_extra_tokens_is_rejected(self) -> None:
        self.assert_invalid_backtick_info_rejected(
            "`````bash fixture`mode extra\n"
            "cargo test --locked -p active-package --all-targets\n"
            "`````"
        )

    def test_container_invalid_backtick_fence_is_rejected_before_credit(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_required_command(
                root,
                "> ```sh `\n"
                "> cargo test --locked -p active-package --all-targets\n"
                "> ```",
            )
            with self.assertRaisesRegex(
                VERIFY.VerificationError,
                "backtick fenced-code info string contains a backtick",
            ):
                VERIFY.verify(root)

    def test_tilde_fence_info_may_contain_backtick(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_required_command(
                root,
                "~~~sh `literal-info\n"
                "cargo test --locked -p active-package --all-targets\n"
                "~~~",
            )
            VERIFY.verify(root)

    def test_indented_visible_list_markdown_link_remains_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            self.replace_contract(
                root,
                "- component details\n"
                "  [MOD-FIXTURE](../docs/modules/MOD-FIXTURE.md)",
            )
            VERIFY.verify(root)

    def test_indented_html_inside_text_fence_remains_allowed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.write_fixture(root)
            path = root / "active/README.md"
            path.write_text(
                path.read_text(encoding="utf-8")
                + "\n```text\n    <div>example only</div>\n```\n",
                encoding="utf-8",
            )
            VERIFY.verify(root)


if __name__ == "__main__":
    unittest.main()
