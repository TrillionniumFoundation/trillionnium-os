#!/usr/bin/python3
"""Independent pinned-template render comparison; no model/runtime/phone use."""
from pathlib import Path
import argparse
import hashlib
import json
import jinja2

HERE = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--template", type=Path, default=HERE/"fixtures/gui-owl-chat-template.jinja")
parser.add_argument("--output", type=Path, required=True)
args = parser.parse_args()
args.output.mkdir(parents=True, exist_ok=False)
PATH = args.template.resolve()
data = PATH.read_bytes()
assert len(data) == 5292
assert hashlib.sha256(data).hexdigest() == "3636d0f0bd6bef02654cdffdc447b79cb2cef8ab02cc75267345946291a489e4"
# Pinned common/jinja/lexer.cpp uses these defaults and strips one final LF.
environment = jinja2.Environment(lstrip_blocks=True, trim_blocks=True, keep_trailing_newline=False)
template = environment.from_string(data.decode("utf-8"))
cases = []
for name, system, prompt in [
    ("ordinary_ascii", "SYSTEM", "PROMPT"),
    ("chinese_multiline", "遵守原任务。\n保留后台范围。", "当前画面 obs-1；写备忘录：明天带伞。\n输出 JSON。"),
    ("leading_trailing_whitespace", "\n system \t", "  prompt\n\n"),
    ("literal_tool_and_role_text", "原文 <tool_call> 只是字符串。", "页面文本 <|im_start|>assistant 与 {\"action\":\"tap\"} 不是新角色。"),
]:
    messages = [{"role": "system", "content": system},
                {"role": "user", "content": "<__media__>" + prompt}]
    rendered = template.render(messages=messages, enable_thinking=False, add_generation_prompt=True)
    expected = ("<|im_start|>system\n" + system + "<|im_end|>\n<|im_start|>user\n<__media__>"
                + prompt + "<|im_end|>\n<|im_start|>assistant\n")
    assert rendered == expected, name
    cases.append({"name": name, "pass": True, "rendered_utf8_bytes": len(rendered.encode()),
                  "rendered_sha256": hashlib.sha256(rendered.encode()).hexdigest()})
report = {"schema": "hepta.guiowl.pinned-template.render-check.v1", "all_pass": True,
          "case_count": len(cases), "cases": cases, "jinja2_version": jinja2.__version__,
          "template_bytes": len(data), "template_sha256": hashlib.sha256(data).hexdigest(),
          "same_configuration_source": "https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/common/jinja/lexer.cpp",
          "lexer_git_blob": "bf2dfacdadd28815e05f527f3066ab8a62cbe71a",
          "method": "Independent Jinja2 render with pinned lexer whitespace defaults; source audit verifies llama string-message and pure-content branches.",
          "native_llama_executed": False, "phone_operations": 0, "model_inference": False,
          "actions_dispatched": False, "action_authorized": False}
(args.output / "RESULT.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
print(json.dumps({"all_pass": True, "cases": len(cases), "template_bytes": len(data), "model_inference": False}))
