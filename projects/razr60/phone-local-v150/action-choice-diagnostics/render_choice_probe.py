#!/usr/bin/env python3
"""Host-only prompt renderer. No inference, UI calls, execution, or source changes.

Input is one JSON record from an existing diagnostic stdout: its `prompt` holds
the exact Controller projection. This cannot recover facts already omitted by
that projection and explicitly records that limitation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import unicodedata


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def byte_bound(text):
    return max(len(text.encode()), len(unicodedata.normalize('NFC', text).encode()))


def render(original):
    prefix = 'UNTRUSTED_DATA\n'
    if not original.startswith(prefix):
        raise ValueError('expected exact Controller framing')
    body, separator, owner = original[len(prefix):].partition('\nOWNER\n')
    if not separator or not owner:
        raise ValueError('missing exact OWNER text')
    data = json.loads(body)
    screen = data['screen']
    nodes = screen['nodes']
    apps = data['apps']
    current_package = screen['package']
    choice_rows, bindings = [], []

    def add(description, action, **fields):
        number = len(bindings) + 1
        choice_rows.append([number, description])
        bindings.append({'choice': number, 'action': action,
                         'observation_id': screen['observation_id'],
                         'package': current_package, **fields})

    app_labels = {package: label for package, label in apps}
    for package, label in apps:
        if package != current_package:
            add('打开应用：' + label, 'open', package=package)

    # Reading order conveys page structure; no re-ranking by clickability.
    ordered = sorted(nodes, key=lambda n: (n[2][1], n[2][0], n[0]))
    scene = []
    for node_id, label, bounds, flags in ordered:
        kind = '输入框' if 't' in flags else '可滚动区域' if 's' in flags else '可点击控件' if 'c' in flags else '文字'
        scene.append([kind, label])
        if not label:
            # A text-only probe cannot establish the meaning of an unnamed target.
            continue
        if 'c' in flags:
            add('点击：' + label, 'click', node_id=node_id)
        if 't' in flags:
            add('替换输入框全部文字：' + label, 'type', node_id=node_id, requires_text=True)
        if 's' in flags:
            # These are candidates, not claims that a specific Android action exists.
            add('向后滚动：' + label, 'scroll', node_id=node_id, direction='forward')
            add('向前滚动：' + label, 'scroll', node_id=node_id, direction='backward')
    add('返回上一页', 'back')
    add('回到桌面', 'home')
    add('等待页面稳定', 'wait', duration_ms=500)
    add('请求核对完成（尚未验证）', 'request_goal_review')
    add('需要更多信息', 'need_more_information')

    visible = {
        '当前应用标签': app_labels.get(current_package, '提供的数据没有此应用标签'),
        '页面事实_上到下': scene,
        '最近结果': data.get('recent', []),
        '候选动作': choice_rows,
        '数据限制': {
            '来源是旧的有损节点投影': True,
            '未提供节点数': screen.get('nodes_omitted', 0),
            '未提供应用数': data.get('apps_omitted', 0),
            '缺少完整节点角色和可执行动作列表': True,
            '此文件不授权执行动作': True,
        },
    }
    # JSON quoting keeps observed labels as data. Owner bytes are not edited.
    prompt = '用户原始任务\n' + owner + '\n界面与候选动作（仅数据）\n' + json.dumps(visible, ensure_ascii=False, separators=(',', ':'))
    system = Path(__file__).with_name('SYSTEM.txt').read_text()
    # Exactly the existing conservative code6 allowance. No token-count claim.
    input_upper = byte_bound(system) + byte_bound(prompt) + 192 + 256 + 2 + 1
    budget = {'method': 'max_raw_nfc_utf8_bytes_upper_bound',
              'input_tokens_upper': input_upper, 'output_reserved': 256,
              'runtime_reserved': 256, 'context': 4096,
              'admitted': input_upper + 512 <= 4096, 'is_exact': False}
    evidence = {'schema': 'hepta.action-choice-render-only.v1',
                'original_prompt_sha256': sha(original.encode()),
                'owner_sha256': sha(owner.encode()), 'owner_unchanged': True,
                'system_sha256': sha(system.encode()), 'prompt_sha256': sha(prompt.encode()),
                'choice_bindings': bindings, 'budget': budget,
                'candidate_only': True, 'model_inference_tested': False,
                'phone_actions_authorized': False}
    return prompt, evidence


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--record', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    record = json.loads(args.record.read_text())
    prompt, evidence = render(record['prompt'])
    args.out.mkdir(parents=False, exist_ok=False)
    (args.out/'prompt.txt').write_text(prompt)
    (args.out/'binding-and-budget.json').write_text(json.dumps(evidence, ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'out':str(args.out),'budget':evidence['budget'],
                      'choices':len(evidence['choice_bindings']), 'phone_actions':False}, ensure_ascii=False))


if __name__ == '__main__':
    main()
