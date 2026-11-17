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
    return json.dumps(dict(reason=fields.pop('reason','根据当前页面推进用户任务'),action=action,observation_id=OBS,package=package,**fields),ensure_ascii=False,separators=(',',':')).replace('\u2028','\\u2028').replace('\u2029','\\u2029')

class GrammarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.labeled=Recognizer((DIRECTORY/'labeled-targets.gbnf').read_text())
        cls.all=Recognizer((DIRECTORY/'all.gbnf').read_text())
        cls.query_entry=Recognizer((DIRECTORY/'query-entry-compact.gbnf').read_text())
        cls.system=Recognizer((DIRECTORY/'system.gbnf').read_text())
        cls.discovery_before=Recognizer((DIRECTORY/'discovery-before.gbnf').read_text())
        cls.discovery_after=Recognizer((DIRECTORY/'discovery-after.gbnf').read_text())
        cls.repeat_before=Recognizer((DIRECTORY/'repeat-before.gbnf').read_text())
        cls.repeat_blocked=Recognizer((DIRECTORY/'repeat-blocked.gbnf').read_text())
        cls.repeat_discovery=Recognizer((DIRECTORY/'repeat-discovery-preserved.gbnf').read_text())
        cls.repeat_home=Recognizer((DIRECTORY/'repeat-home-restored.gbnf').read_text())
    def test_each_action_has_legal_fields(self):
        for sample in [raw('open','com.android.settings'),raw('click',node_label='',node_id='n11'),
                raw('type',node_label='',node_id='n2',text='中文😀\nline "\\'),raw('scroll',node_label='',node_id='n3',direction='down'),
                raw('back'),raw('home'),raw('wait',duration_ms=100),raw('wait',duration_ms=2000),
                raw('find_app',query='calculator',offset=0),
                raw('done',status='success',summary='页面可见')]:
            with self.subTest(sample=sample):self.assertTrue(self.all.accepts(sample))
    def test_real_failure_open_with_node_id_is_impossible(self):
        self.assertFalse(self.all.accepts(raw('open','com.android.settings',node_label='',node_id='n11',reason='打开系统设置，停留在设置首页。')))
        self.assertTrue(self.all.accepts(raw('open','com.android.settings',reason='打开系统设置，停留在设置首页。')))
    def test_navigation_rejects_inapplicable_fields(self):
        for name in ['open','back','home']:
            pkg='com.android.settings' if name=='open' else CURRENT
            self.assertFalse(self.all.accepts(raw(name,pkg,node_label='',node_id='n1')))
            self.assertFalse(self.all.accepts(raw(name,pkg,text='extra')))
    def test_required_fields_and_action_specific_nodes(self):
        for sample in [raw('click'),raw('type',node_label='',node_id='n2'),raw('type',node_label='',node_id='n1',text='wrong field'),
                raw('scroll',node_label='',node_id='n1',direction='down'),raw('click',node_label='',node_id='n2'),
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
        self.assertFalse(self.all.accepts(raw('scroll',node_label='',node_id='n3',direction='diagonal')))
        self.assertFalse(self.all.accepts(raw('done',status='maybe',summary='x')))
    def test_unicode_string_and_control_bounds(self):
        self.assertTrue(self.all.accepts(raw('back',reason='😀'*24)))
        self.assertFalse(self.all.accepts(raw('back',reason='😀'*25)))
        self.assertTrue(self.all.accepts(raw('type',node_label='',node_id='n2',text='😀'*1024)))
        self.assertFalse(self.all.accepts(raw('type',node_label='',node_id='n2',text='😀'*1025)))
        self.assertFalse(self.all.accepts(raw('type',node_label='',node_id='n2',text='\0')))
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
        self.assertFalse(self.all.accepts(' \n'+good+'\t'))
        self.assertTrue(self.all.accepts(' '+good+' '))
    def test_system_window_has_only_available_actions(self):
        self.assertTrue(self.system.accepts(raw('back','android')))
        self.assertTrue(self.system.accepts(raw('done','android',status='partial',summary='需要更多界面信息')))
        self.assertFalse(self.system.accepts(raw('open','android')))
        self.assertFalse(self.system.accepts(raw('click','android',node_label='',node_id='n1')))
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
                raw('find_app',query='',offset=0,node_label='',node_id='n1'),raw('find_app',query='',offset=0,text='launch'),
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
        self.assertFalse(self.discovery_after.accepts(raw('open',target,node_label='',node_id='n1')))

    def test_repeat_guard_masks_only_known_unchanged_launch(self):
        target='com.example.reader'
        self.assertTrue(self.repeat_before.accepts(raw('open',target)))
        self.assertFalse(self.repeat_blocked.accepts(raw('open',target)))
        self.assertTrue(self.repeat_blocked.accepts(raw('open','com.example.notes')))
        for sample in [raw('click',node_label='',node_id='n1'),raw('back'),raw('home'),
                raw('wait',duration_ms=100),raw('find_app',query='reader',offset=0),
                raw('done',status='partial',summary='需要根据当前页面继续导航')]:
            self.assertTrue(self.repeat_blocked.accepts(sample))
        self.assertFalse(self.repeat_blocked.accepts(raw('open',CURRENT)))

    def test_repeat_guard_preserves_discovery_and_ordered_navigation(self):
        target='com.example.reader'
        self.assertFalse(self.repeat_discovery.accepts(raw('open',target)))
        self.assertTrue(self.repeat_home.accepts(raw('open',target)))
        self.assertFalse(self.repeat_home.accepts(raw('open','com.example.unknown')))

    def test_label_then_id_alternatives_are_pairs_not_a_cartesian_product(self):
        pairs={'n12':'1','n13':'2','n14':'3','n3':'除','n7':'乘','n20':'重复','n21':'重复',
            'n22':'','n23':'','n24':'引号"\\\n中文😀','n25':'x\0y\u2028z\u2029',
            'n26':'12345678901234567890123456789012345…'}
        for node_id,label in pairs.items():
            for candidate in set(pairs.values()):
                with self.subTest(node_id=node_id,label=candidate):
                    self.assertEqual(self.labeled.accepts(raw('click',node_label=candidate,node_id=node_id)),candidate==label)

    def test_label_is_required_and_precedes_its_exact_id(self):
        for sample in [raw('click',node_id='n12'),raw('click',node_label='1'),
                raw('click',node_id='n12',node_label='1'),raw('click',node_label='unknown',node_id='n12'),
                raw('click',node_label='1',node_id='n99'),raw('click',node_label=' 1',node_id='n12')]:
            self.assertFalse(self.labeled.accepts(sample))
        good=raw('click',node_label='1',node_id='n12')
        self.assertFalse(self.labeled.accepts(good.replace(OBS,'0'*32)))
        self.assertFalse(self.labeled.accepts(good.replace(CURRENT,'com.example.other')))

    def test_label_pairs_preserve_action_capabilities(self):
        self.assertTrue(self.labeled.accepts(raw('type',node_label='引号"\\\n中文😀',node_id='n24',text='new')))
        self.assertTrue(self.labeled.accepts(raw('scroll',node_label='重复',node_id='n20',direction='down')))
        self.assertFalse(self.labeled.accepts(raw('type',node_label='1',node_id='n12',text='new')))
        self.assertFalse(self.labeled.accepts(raw('scroll',node_label='重复',node_id='n21',direction='down')))

    def test_reason_never_selects_or_repairs_the_pair(self):
        self.assertTrue(self.labeled.accepts(raw('click',reason='点击文字3的n14',node_label='1',node_id='n12')))
        self.assertFalse(self.labeled.accepts(raw('click',reason='点击文字3的n14',node_label='3',node_id='n12')))

    def test_compact_separator_whitespace_is_zero_or_one_ascii_space(self):
        good=raw('click',node_label='',node_id='n1')
        spaced=json.dumps(json.loads(good),ensure_ascii=False,separators=(', ', ': '))
        self.assertTrue(self.all.accepts(good))
        self.assertTrue(self.all.accepts(' '+spaced+' '))
        for padding in ['  ',' '*8,'\t','\n','\r','\r\n','\u00a0']:
            with self.subTest(padding=repr(padding)):
                self.assertFalse(self.all.accepts(padding+good))
                self.assertFalse(self.all.accepts(good+padding))
                self.assertFalse(self.all.accepts(good.replace(',"action"',','+padding+'"action"',1)))
                self.assertFalse(self.all.accepts(good.replace(':"click"',':'+padding+'"click"',1)))
    def test_short_reason_scalar_bound_includes_escaped_characters(self):
        for reason in ['字','字'*24,'😀'*24,'"\n\\'*8]:
            self.assertEqual(len(reason),1 if reason=='字' else 24)
            self.assertTrue(self.all.accepts(raw('back',reason=reason)))
        for reason in ['', '字'*25, '😀'*25, '"\n\\'*8+'x', 'x'*96]:
            self.assertFalse(self.all.accepts(raw('back',reason=reason)))
    def test_string_content_whitespace_and_body_bounds_are_unchanged(self):
        text='正文'+' '*8+'\n\t第二行'
        self.assertTrue(self.all.accepts(raw('type',node_label='',node_id='n2',text=text)))
        self.assertTrue(self.all.accepts(raw('type',node_label='',node_id='n2',text='😀'*1024)))
        self.assertFalse(self.all.accepts(raw('type',node_label='',node_id='n2',text='😀'*1025)))
        self.assertTrue(self.all.accepts(raw('done',status='partial',summary='字'*1024)))
        self.assertFalse(self.all.accepts(raw('done',status='partial',summary='字'*1025)))
    def test_synthetic_query_entry_retains_exact_domain_and_completion(self):
        fields=dict(node_label='搜索推荐商品优惠',node_id='n16')
        click=raw('click','com.example.catalog',reason='进入查询入口',**fields)
        self.assertTrue(self.query_entry.accepts(click))
        self.assertTrue(self.query_entry.accepts(raw('wait','com.example.catalog',duration_ms=100)))
        self.assertTrue(self.query_entry.accepts(raw('done','com.example.catalog',status='partial',summary='结果条件尚未满足')))
        invalid=[
            raw('done','com.example.catalog',status='success',summary='查到结果'),
            raw('type','com.example.catalog',node_label=fields['node_label'],node_id='n16',text='新查询'),
            raw('home','com.example.catalog'),raw('back','com.example.catalog'),
            raw('open','com.example.catalog'),raw('click','com.example.catalog',node_label='推荐商品',node_id='n16'),
            raw('click','com.example.catalog',node_label=fields['node_label'],node_id='n17'),
            click.replace(OBS,'0'*32),click.replace('com.example.catalog','com.example.other'),
            click[:-1],click[:click.index('"node_id"')+5],click+'\n{}',
        ]
        for value in invalid:
            with self.subTest(value=value):self.assertFalse(self.query_entry.accepts(value))
    def test_partial_object_cannot_be_completed_or_dispatched_by_recognition(self):
        complete=raw('click',node_label='',node_id='n1')
        for limit in [0,1,complete.index('"action"'),complete.index('"node_id"')+5,len(complete)-1]:
            self.assertFalse(self.all.accepts(complete[:limit]))

if __name__=='__main__':unittest.main(verbosity=2)
