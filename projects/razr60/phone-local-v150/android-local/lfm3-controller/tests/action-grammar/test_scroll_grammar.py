"""Recognize actual generated GBNF, including rejected node/direction cross-products."""
import json
from pathlib import Path
import sys
from gbnf_recognizer import Recognizer

directory=Path(sys.argv[1])
grammar=Recognizer((directory/'scroll-directions.gbnf').read_text())
none=Recognizer((directory/'scroll-unavailable.gbnf').read_text())
labels={'n1':'','n2':'','n3':'unknown','n4':'empty'}
expected={'n1':{'forward'},'n2':{'down','left'},'n3':set(),'n4':set()}
checked=0
for node,label in labels.items():
    for direction in ('forward','backward','up','down','left','right'):
        raw=json.dumps(dict(reason='Use only the observed direction.',action='scroll',
            observation_id='f91c685bf5f04f5c9a6a3197eade1fed',package='com.example.launcher',
            node_label=label,node_id=node,direction=direction),ensure_ascii=False,separators=(',',':'))
        assert grammar.accepts(raw)==(direction in expected[node]),(node,direction)
        assert not none.accepts(raw),(node,direction,'empty branch')
        checked+=1
bad=json.dumps(dict(reason='Do not reuse another node.',action='scroll',
    observation_id='f91c685bf5f04f5c9a6a3197eade1fed',package='com.example.launcher',
    node_label='unknown',node_id='n1',direction='forward'),separators=(',',':'))
assert not grammar.accepts(bad),'label binding still required'
print(json.dumps({'node_direction_cases':checked,'unavailable_branch_cases':checked,
    'label_binding_rejects':1,'native_grammar_executed':False,'phone_contacted':False}))
