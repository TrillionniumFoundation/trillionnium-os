"""Generate fictional Settings evidence for public host tests.

No captured phone file, screenshot, serial, task ID or user data is read here.
These receipts exercise parsing/binding only and must never qualify a phone.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

import core_assertions as checks
import core_phone_suite as core
from test_core_assertions import Evidence, write


def system_window(number, label, kind, frame, visible=True):
    value = "true" if visible else "false"
    return (
        "  Window #%d Window{synthetic%d u0 %s}:\n" % (number, number, label)
        + "    mDisplayId=0\n"
        + "    mOwnerUid=1000 showForAllUsers=true package=com.android.systemui appop=NONE\n"
        + "    mAttrs={ty=%s}\n" % kind
        + "    mViewVisibility=0x0 mObscured=false\n"
        + "    mHasSurface=%s isReadyForDisplay()=%s\n" % (value, value)
        + "    Frames: frame=%s\n" % frame
        + "    isOnScreen=%s\n    isVisible=%s\n" % (value, value)
    )


def terminal(root, step, title, nodes, xml):
    """Replace synthetic page content and rebind its synthetic native prompt."""
    prefix = root / "task" / ("step-%02d" % step)
    values = {}
    for suffix in ("before", "after"):
        path = Path(str(prefix) + "-" + suffix + ".json")
        value = json.loads(path.read_text())
        value["nodes"] = nodes
        value["window"]["title"] = title
        write(path, value)
        values[suffix] = value
    action = json.loads(Path(str(prefix) + "-action.json").read_text())
    run = root / "runs" / action["model_run_id"]
    prompt_path = run / "prompt.txt"
    payload, owner = prompt_path.read_text()[len("UNTRUSTED_DATA\n"):].split("\nOWNER\n", 1)
    prompt = json.loads(payload)
    prompt["screen"]["nodes"] = [[n["id"], n["text"], n["bounds"], ""] for n in nodes]
    prompt["screen"]["window"]["title"] = title
    raw = ("UNTRUSTED_DATA\n" + json.dumps(prompt, ensure_ascii=False) + "\nOWNER\n" + owner).encode()
    prompt_path.write_bytes(raw)
    native = json.loads((run / "native-result.json").read_text())
    native["input_sha256"]["prompt"] = hashlib.sha256(raw).hexdigest()
    write(run / "native-result.json", native)
    (root / "ui-final.xml").write_bytes(ET.tostring(xml))


def generate(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=False)
    plan = {"schema": "hepta.synthetic-oracle-plan.v1", "synthetic": True, "cases": core.templates()}
    # Reproduce the former collapsible-title predicate without copying a plan.
    for case in plan["cases"]:
        if case["assertion"] in checks.HOME_KINDS:
            case["expected_visible_text"] = ["设置", "搜索设置"]
    write(root / "original-plan.json", plan)
    for kind, count in (("settings_home", 2), ("cross_app", 4), ("search_return_home", 3)):
        case = next(c for c in plan["cases"] if c["assertion"] == kind)
        directory = root / "cases" / case["case_id"]
        evidence = Evidence(directory, kind)
        for _ in range(count - 1):
            evidence.event("back", checks.SETTINGS)
        evidence.homepage_ui()
        home_dump = (directory / "ui-final-window.txt").read_text()
        body = home_dump.split("\n", 1)[1].split("  mTopFocusedDisplayId=", 1)[0]
        bars = system_window(1, "StatusBar", "STATUS_BAR", "[0,0][720,15]")
        bars += system_window(2, "NavigationBar0", "NAVIGATION_BAR", "[0,1265][720,1280]")
        wallpaper = system_window(3, "SyntheticWallpaper", "WALLPAPER", "[0,0][720,1280]", False)
        dump = "WINDOW MANAGER WINDOWS (synthetic)\n" + bars + body + wallpaper
        dump += "  Hiding System Alert Windows:\n" + body.replace("  Window #0 ", "  #0 ", 1)
        dump += "  mTopFocusedDisplayId=0\n"
        (directory / "ui-final-window.txt").write_text(dump)
        if kind == "search_return_home":
            # A real type of false positive: searchable Settings child page plus
            # a hidden home activity in WMS. All bytes here remain fictional.
            hidden = body.replace("mViewVisibility=0x0", "mViewVisibility=0x8").replace("mObscured=false", "mObscured=true")
            hidden = hidden.replace("mHasSurface=true", "mHasSurface=false").replace("isReadyForDisplay()=true", "isReadyForDisplay()=false")
            hidden = hidden.replace("isVisible=true", "isVisible=false").replace("isOnScreen=true", "isOnScreen=false")
            hidden = "\n".join(line for line in hidden.splitlines() if "Surface: shown=" not in line) + "\n"
            child = body.replace("Window #0", "Window #4").replace(".Settings", ".SubSettings")
            dump = "WINDOW MANAGER WINDOWS (synthetic)\n" + bars + hidden + child + wallpaper
            dump += "  mTopFocusedDisplayId=0\n"
            (directory / "ui-final-window.txt").write_text(dump)
            xml = ET.Element("hierarchy", {"rotation": "0"})
            page = ET.SubElement(xml, "node", {"package": checks.SETTINGS, "class": "android.widget.FrameLayout",
                "bounds": "[0,0][720,1280]", "enabled": "true", "resource-id": checks.SETTINGS + ":id/content_parent"})
            nodes = []
            for i, text in enumerate(("搜索设置", "系统", "语言", "日期和时间")):
                view_id = checks.SETTINGS + ":id/search_action_bar_title" if i == 0 else "android:id/title"
                box = [20, 20 + i * 120, 200, 60 + i * 120]
                ET.SubElement(page, "node", {"package": checks.SETTINGS, "class": "android.widget.TextView",
                    "resource-id": view_id, "text": text, "enabled": "true", "bounds": "[%d,%d][%d,%d]" % tuple(box)})
                nodes.append({"id": "synthetic%d" % i, "view_id": view_id, "text": text, "bounds": box})
            terminal(directory, count, "系统", nodes, xml)
    files = []
    for path in sorted(root.rglob("*")):
        if path.is_file():
            raw = path.read_bytes()
            files.append({"dest": "fixtures/" + path.relative_to(root).as_posix(),
                          "bytes": len(raw), "sha": hashlib.sha256(raw).hexdigest()})
    manifest = {"schema": "hepta.homepage-oracle-synthetic-fixtures.v1", "synthetic": True,
                "real_phone_evidence_included": False, "files": files}
    write(root.parent / "EVIDENCE-SOURCES.json", manifest)
    return manifest
