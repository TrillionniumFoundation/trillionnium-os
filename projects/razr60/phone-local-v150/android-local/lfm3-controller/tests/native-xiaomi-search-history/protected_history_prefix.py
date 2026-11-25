"""Exact whole-file proof-copy inverse for the reviewed single-history prefix.

Only known parent/current bytes are accepted. Actual javac continues using the
current production source; no runtime node or permission is transformed.
"""
import hashlib
CURRENT_SHA = "6802c799ab5308594b9f817a3f00439f95ec3a27d5be991e2c3ea6138638b074"
PARENT_SHA = "ecf6a9ccf173dc78c6c167435dc745b4080aa85a4fb77b22c3d442b7674254c3"
INVERSES = [
  [
    "            if(!filled||i<4)bottom=Math.max(bottom,Math.max(n.bounds.get(1),n.bounds.get(3)));\n        }\n        need(enclosure.bounds.get(1)>=bottom&&coordinatesWithin(root,enclosure),\"recommendations disjoint from entire query/action toolbar\");\n        int recommendationStart=0;\n        if(\"搜索历史\".equals(snapshot.node(\"0/6/0\").text)){\n            requireSingleHistoryPrefix(snapshot,enclosure);\n            recommendationStart=2;\n        }\n        Node heading=snapshot.node(\"0/6/\"+recommendationStart),refresh=snapshot.node(\"0/6/\"+(recommendationStart+1));\n        need(TEXT.equals(heading.cls)&&\"android.widget.ScrollView\".equals(heading.parent)&&heading.children==0\n                &&heading.usable()&&\"猜你想搜\".equals(heading.text)&&!b(heading.v,\"clickable\")\n                &&!b(heading.v,\"action_click\")&&passiveMetadata(heading)&&coordinatesWithin(enclosure,heading),\"actual recommendation section heading\");\n",
    "            if(!filled||i<4)bottom=Math.max(bottom,Math.max(n.bounds.get(1),n.bounds.get(3)));\n        }\n        need(enclosure.bounds.get(1)>=bottom&&coordinatesWithin(root,enclosure),\"recommendations disjoint from entire query/action toolbar\");\n        Node heading=snapshot.node(\"0/6/0\"),refresh=snapshot.node(\"0/6/1\");\n        need(TEXT.equals(heading.cls)&&\"android.widget.ScrollView\".equals(heading.parent)&&heading.children==0\n                &&heading.usable()&&\"猜你想搜\".equals(heading.text)&&!b(heading.v,\"clickable\")\n                &&!b(heading.v,\"action_click\")&&passiveMetadata(heading)&&coordinatesWithin(enclosure,heading),\"actual recommendation section heading\");\n"
  ],
  [
    "                &&b(refresh.v,\"clickable\")&&b(refresh.v,\"action_click\")&&passiveMetadata(refresh)\n                &&coordinatesWithin(enclosure,refresh),\"same observed recommendation refresh control\");\n        Set<String> chips=new TreeSet<String>();Node carousel=null;\n        for(int index=recommendationStart+2;index<enclosure.children;index++){\n            Node chip=snapshot.node(\"0/6/\"+index);\n            if(!VIEW.equals(chip.cls)||chip.children!=1){carousel=chip;break;}\n            need(index<34,\"bounded complete recommendation chip run\");\n",
    "                &&b(refresh.v,\"clickable\")&&b(refresh.v,\"action_click\")&&passiveMetadata(refresh)\n                &&coordinatesWithin(enclosure,refresh),\"same observed recommendation refresh control\");\n        Set<String> chips=new TreeSet<String>();Node carousel=null;\n        for(int index=2;index<enclosure.children;index++){\n            Node chip=snapshot.node(\"0/6/\"+index);\n            if(!VIEW.equals(chip.cls)||chip.children!=1){carousel=chip;break;}\n            need(index<34,\"bounded complete recommendation chip run\");\n"
  ],
  [
    "                &&coordinatesWithin(enclosure,carousel),\"fixed passive horizontal carousel leaf and known boundary directions\");\n        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,carousel);\n        return new Template(chips,carousel.path);\n    }\n    /** The recorded one-item history prefix is protected, never variable.\n     * It grants no history-item click or query submission. The complete pair\n     * comparison still requires every prefix node to be byte-for-byte equal. */\n    private static void requireSingleHistoryPrefix(Snapshot snapshot,Node enclosure){\n        Node heading=snapshot.node(\"0/6/0\"),item=snapshot.node(\"0/6/1\"),text=snapshot.node(\"0/6/1/0\");\n        need(TEXT.equals(heading.cls)&&\"android.widget.ScrollView\".equals(heading.parent)&&heading.children==0\n                &&heading.usable()&&heading.view.isEmpty()&&heading.desc.isEmpty()\n                &&\"搜索历史\".equals(heading.text)&&\"搜索历史\".equals(heading.label)\n                &&!b(heading.v,\"clickable\")&&!b(heading.v,\"action_click\")&&passiveMetadata(heading)\n                &&coordinatesWithin(enclosure,heading),\"complete observed search-history heading\");\n        need(VIEW.equals(item.cls)&&\"android.widget.ScrollView\".equals(item.parent)&&item.children==1\n                &&item.click()&&item.view.isEmpty()&&item.text.isEmpty()&&item.desc.isEmpty()\n                &&\"AX3000T\".equals(item.label)&&passiveMetadata(item)\n                &&TEXT.equals(text.cls)&&VIEW.equals(text.parent)&&text.children==0&&text.usable()\n                &&text.view.isEmpty()&&text.desc.isEmpty()&&\"AX3000T\".equals(text.text)&&\"AX3000T\".equals(text.label)\n                &&!b(text.v,\"clickable\")&&!b(text.v,\"action_click\")&&passiveMetadata(text)\n                &&coordinatesWithin(enclosure,item)&&coordinatesWithin(item,text)\n                &&heading.bounds.get(3)<=item.bounds.get(1)\n                &&item.bounds.get(3)<=snapshot.node(\"0/6/2\").bounds.get(1),\"complete observed single search-history item\");\n        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,heading);\n        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,item);\n        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,text);\n    }\n    private static void toolbarButton(Snapshot s,Node button){\n        Node label=s.node(button.path+\"/0\");\n",
    "                &&coordinatesWithin(enclosure,carousel),\"fixed passive horizontal carousel leaf and known boundary directions\");\n        NativeActionSnapshotCheck.requireSearchInputReference(snapshot,carousel);\n        return new Template(chips,carousel.path);\n    }\n    private static void toolbarButton(Snapshot s,Node button){\n        Node label=s.node(button.path+\"/0\");\n"
  ]
]

def predecessor(raw):
    if not isinstance(raw, bytes):
        raise ValueError("exact source bytes required")
    digest = hashlib.sha256(raw).hexdigest()
    if digest == PARENT_SHA:
        return raw
    if digest != CURRENT_SHA:
        raise ValueError("reviewed current single-history input source required")
    for current, parent in reversed(INVERSES):
        current, parent = current.encode("utf-8"), parent.encode("utf-8")
        if raw.count(current) != 1:
            raise ValueError("single-history inverse must attach exactly once")
        raw = raw.replace(current, parent, 1)
    if hashlib.sha256(raw).hexdigest() != PARENT_SHA:
        raise ValueError("single-history inverse must reproduce complete 1fab input source")
    return raw
