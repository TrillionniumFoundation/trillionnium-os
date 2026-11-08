"""Check the real controller SYSTEM and production-generated completion grammar."""
import json
from pathlib import Path
import re
import sys
from gbnf_recognizer import Recognizer

root=Path(__file__).resolve().parents[2]
source=(root/"src/org/trillionnium/hepta/local/LocalTaskController.java").read_text()
matched=re.search(r'private static final String SYSTEM\s*=\s*((?:"(?:[^"\\]|\\.)*"\s*\+?\s*)+);',source)
assert matched,"actual Java SYSTEM literal declaration missing"
parts=re.findall(r'"(?:[^"\\]|\\.)*"',matched.group(1))
assert not re.sub(r'"(?:[^"\\]|\\.)*"',"",matched.group(1)).replace("+","").strip()
system="".join(json.loads(part) for part in parts)
menu=[line for line in system.splitlines() if line.startswith("工具：")]
assert len(menu)==1 and "done(status,summary)" in menu[0]
assert "status=success/partial/failure" in menu[0]
assert "仅在页面仍在加载时等待100..2000毫秒" in menu[0]
assert "done必须同时包含status和summary" in system
assert "action必须是工具名字符串，不能为null" in system
assert "wait只表示暂时等待加载，不能表示完成或停留" in system
assert 'action="done",status="success"' in system
assert "按原顺序完成且有可见证据" in system and "OWNER 是用户任务" in system

grammar=Recognizer((Path(sys.argv[1])/"all.gbnf").read_text())
def decision(action,**fields):
    value=dict(reason="当前观察足以核对任务结果",action=action,
               observation_id="f91c685bf5f04f5c9a6a3197eade1fed",package="com.example.launcher",**fields)
    return json.dumps(value,ensure_ascii=False,separators=(",",":"))
for status in ("success","partial","failure"):
    assert grammar.accepts(decision("done",status=status,summary="根据当前观察报告结果"))
for invalid in (decision(None),decision("done"),decision("done",status="success"),
                decision("done",summary="缺少状态"),decision("done",status="success",summary="")):
    assert not grammar.accepts(invalid)
assert grammar.accepts(decision("wait",duration_ms=100))
assert not grammar.accepts(decision("wait",duration_ms=100,status="success",summary="把等待当完成"))
print("PASS actual SYSTEM includes completion tool and loading-only wait; production grammar requires string action and all done fields; phone_tested=false")
