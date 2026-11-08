"""Independently recognize actual production-generated GBNF; no phone or model."""
import json
from pathlib import Path
import sys
import unittest
from gbnf_recognizer import Recognizer

DIRECTORY=Path(sys.argv.pop(1))
OBS='f91c685bf5f04f5c9a6a3197eade1fed'
CURRENT='com.example.launcher'

def raw(action,package=CURRENT,**fields):
    return json.dumps(dict(reason=fields.pop('reason','根据当前页面推进用户任务'),action=action,observation_id=OBS,package=package,**fields),ensure_ascii=False,separators=(',',':'))

class GrammarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.all=Recognizer((DIRECTORY/'all.gbnf').read_text())
        cls.system=Recognizer((DIRECTORY/'system.gbnf').read_text())
        cls.discovery_before=Recognizer((DIRECTORY/'discovery-before.gbnf').read_text())
        cls.discovery_after=Recognizer((DIRECTORY/'discovery-after.gbnf').read_text())
        cls.repeat_before=Recognizer((DIRECTORY/'repeat-before.gbnf').read_text())
        cls.repeat_blocked=Recognizer((DIRECTORY/'repeat-blocked.gbnf').read_text())
        cls.repeat_discovery=Recognizer((DIRECTORY/'repeat-discovery-preserved.gbnf').read_text())
        cls.repeat_home=Recognizer((DIRECTORY/'repeat-home-restored.gbnf').read_text())
    def test_each_action_has_legal_fields(self):
        for sample in [raw('open','com.android.settings'),raw('click',node_id='n11'),
                raw('type',node_id='n2',text='中文😀\nline "\\'),raw('scroll',node_id='n3',direction='down'),
                raw('back'),raw('home'),raw('wait',duration_ms=100),raw('wait',duration_ms=2000),
                raw('find_app',query='calculator',offset=0),
                raw('done',status='success',summary='页面可见')]:
            with self.subTest(sample=sample):self.assertTrue(self.all.accepts(sample))
    def test_real_failure_open_with_node_id_is_impossible(self):
        self.assertFalse(self.all.accepts(raw('open','com.android.settings',node_id='n11',reason='打开系统设置，停留在设置首页。')))
        self.assertTrue(self.all.accepts(raw('open','com.android.settings',reason='打开系统设置，停留在设置首页。')))
    def test_navigation_rejects_inapplicable_fields(self):
        for name in ['open','back','home']:
            pkg='com.android.settings' if name=='open' else CURRENT
            self.assertFalse(self.all.accepts(raw(name,pkg,node_id='n1')))
            self.assertFalse(self.all.accepts(raw(name,pkg,text='extra')))
    def test_required_fields_and_action_specific_nodes(self):
        for sample in [raw('click'),raw('type',node_id='n2'),raw('type',node_id='n1',text='wrong field'),
                raw('scroll',node_id='n1',direction='down'),raw('click',node_id='n2'),
                raw('done',status='success'),raw('wait'),raw('click',x=10,y=20)]:
            self.assertFalse(self.all.accepts(sample))
    def test_current_observation_and_package_are_bound(self):
        good=raw('back')
        self.assertFalse(self.all.accepts(good.replace(OBS,'0'*32)))
        self.assertFalse(self.all.accepts(raw('back','com.android.settings')))
        self.assertFalse(self.all.accepts(raw('open',CURRENT)))
        self.assertFalse(self.all.accepts(raw('open','android')))
        self.assertFalse(self.all.accepts(raw('open','com.example.unknown')))
    def test_integer_ranges_and_enums(self):
        for value in [99,2001,-1,100.0,'100',True]:self.assertFalse(self.all.accepts(raw('wait',duration_ms=value)))
        for value in [100,999,1000,1999,2000]:self.assertTrue(self.all.accepts(raw('wait',duration_ms=value)))
        self.assertFalse(self.all.accepts(raw('scroll',node_id='n3',direction='diagonal')))
        self.assertFalse(self.all.accepts(raw('done',status='maybe',summary='x')))
    def test_unicode_string_and_control_bounds(self):
        self.assertTrue(self.all.accepts(raw('back',reason='😀'*96)))
        self.assertFalse(self.all.accepts(raw('back',reason='😀'*97)))
        self.assertTrue(self.all.accepts(raw('type',node_id='n2',text='😀'*1024)))
        self.assertFalse(self.all.accepts(raw('type',node_id='n2',text='😀'*1025)))
        self.assertFalse(self.all.accepts(raw('type',node_id='n2',text='\0')))
        self.assertFalse(self.all.accepts(raw('done',status='success',summary='')))
        self.assertFalse(self.all.accepts(raw('back',reason='x').replace('"x"','"\\uD800"')))
    def test_reason_precedes_action_and_is_bounded(self):
        good=json.loads(raw('back'))
        no_reason={key:value for key,value in good.items() if key!='reason'}
        self.assertFalse(self.all.accepts(json.dumps(no_reason,separators=(',',':'))))
        no_reason['reason']=good['reason']
        self.assertFalse(self.all.accepts(json.dumps(no_reason,separators=(',',':'),ensure_ascii=False)))
        self.assertFalse(self.all.accepts(raw('back',reason='')))

    def test_no_unknown_duplicate_or_trailing_content(self):
        good=raw('back')
        self.assertFalse(self.all.accepts(good[:-1]+',"shell":"id"}'))
        self.assertFalse(self.all.accepts(good[:-1]+',"action":"back"}'))
        self.assertFalse(self.all.accepts(good+good))
        self.assertFalse(self.all.accepts('```json\n'+good+'\n```'))
        self.assertTrue(self.all.accepts(' \n'+good+'\t'))
    def test_system_window_has_only_available_actions(self):
        self.assertTrue(self.system.accepts(raw('back','android')))
        self.assertTrue(self.system.accepts(raw('done','android',status='partial',summary='需要更多界面信息')))
        self.assertFalse(self.system.accepts(raw('open','android')))
        self.assertFalse(self.system.accepts(raw('click','android',node_id='n1')))
        self.assertTrue(self.system.accepts(raw('find_app','android',query='',offset=6)))

    def test_discovery_schema_is_bounded_and_read_only(self):
        for query in ['', '计算器', 'com.example.calc', '😀'*64, 'a\\"b']:
            self.assertTrue(self.all.accepts(raw('find_app',query=query,offset=0)))
        for offset in [0,1,9,10,99,100,999,1000,3999,4000,4089,4090,4095]:
            self.assertTrue(self.all.accepts(raw('find_app',query='',offset=offset)))
        for offset in [-1,4096,4100,9999,0.0,'0',True,None]:
            self.assertFalse(self.all.accepts(raw('find_app',query='',offset=offset)))
        for sample in [raw('find_app',query='x'*65,offset=0),raw('find_app',query='\0',offset=0),
                raw('find_app',query='calc'),raw('find_app',offset=0),
                raw('find_app',query='',offset=0,node_id='n1'),raw('find_app',query='',offset=0,text='launch'),
                raw('find_app','com.android.settings',query='',offset=0),raw('open','com.example.unknown')]:
            self.assertFalse(self.all.accepts(sample))

    def test_discovery_changes_only_observed_open_permissions(self):
        target='com.example.calculator'
        search=raw('find_app',query='calculator',offset=0)
        self.assertTrue(self.discovery_before.accepts(search))
        self.assertFalse(self.discovery_before.accepts(raw('open',target)))
        self.assertTrue(self.discovery_after.accepts(raw('open',target)))
        self.assertFalse(self.discovery_after.accepts(raw('open','com.evil.injected')))
        self.assertFalse(self.discovery_after.accepts(raw('open','com.example.app00')))
        self.assertFalse(self.discovery_after.accepts(raw('open',target,node_id='n1')))

    def test_repeat_guard_masks_only_known_unchanged_launch(self):
        target='com.example.reader'
        self.assertTrue(self.repeat_before.accepts(raw('open',target)))
        self.assertFalse(self.repeat_blocked.accepts(raw('open',target)))
        self.assertTrue(self.repeat_blocked.accepts(raw('open','com.example.notes')))
        for sample in [raw('click',node_id='n1'),raw('back'),raw('home'),
                raw('wait',duration_ms=100),raw('find_app',query='reader',offset=0),
                raw('done',status='partial',summary='需要根据当前页面继续导航')]:
            self.assertTrue(self.repeat_blocked.accepts(sample))
        self.assertFalse(self.repeat_blocked.accepts(raw('open',CURRENT)))

    def test_repeat_guard_preserves_discovery_and_ordered_navigation(self):
        target='com.example.reader'
        self.assertFalse(self.repeat_discovery.accepts(raw('open',target)))
        self.assertTrue(self.repeat_home.accepts(raw('open',target)))
        self.assertFalse(self.repeat_home.accepts(raw('open','com.example.unknown')))

if __name__=='__main__':unittest.main(verbosity=2)
