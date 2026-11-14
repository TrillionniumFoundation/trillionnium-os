"""Recognize actual Java production GBNF; synthetic targets, no model or phone."""
import json
from pathlib import Path
import sys
import unittest

DIRECTORY=Path(sys.argv.pop(1))
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'action-grammar'))
from gbnf_recognizer import Recognizer

OBS='1'*32
HOME='org.example.launcher'
CLOCK='org.example.clock'
OTHER='org.example.mail'

def action(kind,current=HOME,**parameters):
    value={'reason':'根据用户授权选择一步','action':kind,'observation_id':OBS}
    if kind=='open':value['app_label']=parameters.pop('app_label','时钟')
    value['package']=parameters.pop('package',current)
    value.update(parameters)
    return json.dumps(value,ensure_ascii=False,separators=(',',':'))

class OwnerGrammarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grammars={name:Recognizer((DIRECTORY/(name+'.gbnf')).read_text())
                      for name in ('initial','found','pending-open','observed-open','keys')}

    def test_initial_catalogue_does_not_authorize_open_or_success(self):
        grammar=self.grammars['initial']
        self.assertTrue(grammar.accepts(action('find_app',query='时钟',offset=0)))
        self.assertFalse(grammar.accepts(action('open',package=CLOCK)))
        self.assertFalse(grammar.accepts(action('done',status='success',summary='自称完成')))

    def test_discovery_query_cannot_expand_owner_target(self):
        for stage in ('initial','found','pending-open','observed-open'):
            current=CLOCK if stage=='observed-open' else HOME
            for query in ('','邮件','时钟或邮件','时钟 '):
                with self.subTest(stage=stage,query=query):
                    self.assertFalse(self.grammars[stage].accepts(action('find_app',current,query=query,offset=0)))

    def test_actual_found_page_allows_only_its_original_app_pair(self):
        grammar=self.grammars['found']
        self.assertTrue(grammar.accepts(action('open',package=CLOCK)))
        self.assertFalse(grammar.accepts(action('open',package=OTHER,app_label='邮件')))
        self.assertFalse(grammar.accepts(action('open',package=CLOCK,app_label='邮件')))

    def test_open_dispatch_does_not_grant_success_without_observation(self):
        for stage in ('found','pending-open'):
            self.assertFalse(self.grammars[stage].accepts(action('done',status='success',summary='没有后续观察')))
        self.assertTrue(self.grammars['observed-open'].accepts(action('done',CLOCK,status='success',summary='当前目标可见')))

    def test_prohibited_tools_never_reappear_after_discovery_or_open(self):
        for stage in ('initial','found','pending-open','observed-open'):
            current=CLOCK if stage=='observed-open' else HOME
            for sample in (action('click',current,node_label='同意并继续',node_id='n3'),
                           action('type',current,node_label='1',node_id='n1',text='anything'),
                           action('home',current),action('back',current),action('wait',current,duration_ms=100)):
                with self.subTest(stage=stage,sample=sample):self.assertFalse(self.grammars[stage].accepts(sample))

    def test_partial_and_failure_remain_available(self):
        for stage in ('initial','found','pending-open','observed-open'):
            current=CLOCK if stage=='observed-open' else HOME
            for status in ('partial','failure'):
                self.assertTrue(self.grammars[stage].accepts(action('done',current,status=status,summary='不能继续完成')))

    def test_keys_method_keeps_observed_keys_but_excludes_text_replacement(self):
        grammar=self.grammars['keys']
        for node,label in (('n1','1'),('n9','9')):
            self.assertTrue(grammar.accepts(action('click',node_label=label,node_id=node)))
        self.assertFalse(grammar.accepts(action('type',node_label='1',node_id='n1',text='437')))

if __name__=='__main__':unittest.main(verbosity=2)
