from pathlib import Path


def replace_once(text: str, old: str, new: str, label: str) -> str:
    if text.count(old) != 1:
        raise SystemExit(f"R15 {label} anchor is not exact")
    return text.replace(old, new, 1)


path = Path("crates/trillionnium-owner-open-provider-jsonl/src/process.rs")
text = path.read_text()
text = replace_once(
    text,
    "        if result.is_ok() {\n"
    "            self.child.take();\n"
    "        }\n",
    "        if result.is_ok() {\n"
    "            drop(self.child.take());\n"
    "        }\n",
    "provider finished-child must-use result",
)
text = replace_once(
    text,
    "            .spawn(move || {\n"
    "                let Ok(mut slot) = thread_owner.lock() else {\n"
    "                    return;\n"
    "                };\n"
    "                if let Some(mut child) = slot.take() {\n"
    "                    let _ = child.wait();\n"
    "                }\n"
    "            })\n",
    "            .spawn(move || {\n"
    "                let mut slot = match thread_owner.lock() {\n"
    "                    Ok(slot) => slot,\n"
    "                    Err(poisoned) => poisoned.into_inner(),\n"
    "                };\n"
    "                if let Some(mut child) = slot.take() {\n"
    "                    let _ = child.wait();\n"
    "                }\n"
    "            })\n",
    "provider detached reaper poison recovery",
)
text = replace_once(
    text,
    "            if let Ok(mut slot) = owner.lock()\n"
    "                && let Some(mut child) = slot.take()\n"
    "            {\n"
    "                let _ = child.wait();\n"
    "            }\n",
    "            let mut slot = match owner.lock() {\n"
    "                Ok(slot) => slot,\n"
    "                Err(poisoned) => poisoned.into_inner(),\n"
    "            };\n"
    "            if let Some(mut child) = slot.take() {\n"
    "                let _ = child.wait();\n"
    "            }\n",
    "provider fallback reaper poison recovery",
)
path.write_text(text)
