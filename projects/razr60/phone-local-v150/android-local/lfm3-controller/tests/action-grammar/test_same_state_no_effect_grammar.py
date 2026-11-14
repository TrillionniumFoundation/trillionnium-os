"""Recognize actual candidate-filtered, unchanged production GBNF; no model/device."""
import json
from pathlib import Path
import sys
import unittest
from gbnf_recognizer import Recognizer
DIRECTORY=Path(sys.argv.pop(1))
OBS="f91c685bf5f04f5c9a6a3197eade1fed"
PKG="com.example.screen"
def raw(action,package=PKG,**fields):
    return json.dumps(dict(reason="observed decision",action=action,observation_id=OBS,package=package,**fields),separators=(",",":"))
class Contracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before=Recognizer((DIRECTORY/"same-state-before.gbnf").read_text())
        cls.blocked=Recognizer((DIRECTORY/"same-state-blocked.gbnf").read_text())
        cls.changed=Recognizer((DIRECTORY/"same-state-changed.gbnf").read_text())
        cls.returned=Recognizer((DIRECTORY/"same-state-returned.gbnf").read_text())
    def test_multiple_exact_clicks_removed_and_retained_when_state_returns(self):
        for node in ("n1","n2"):
            sample=raw("click",node_label="same label",node_id=node)
            self.assertTrue(self.before.accepts(sample))
            self.assertFalse(self.blocked.accepts(sample))
            self.assertTrue(self.changed.accepts(sample))
            self.assertFalse(self.returned.accepts(sample))
        self.assertTrue(self.blocked.accepts(raw("click",node_label="different",node_id="n3")))
        self.assertFalse(self.blocked.accepts(raw("click",node_label="same label",node_id="n3")))
    def test_multiple_exact_open_packages_removed(self):
        for package in ("com.example.reader","com.example.notes"):
            self.assertTrue(self.before.accepts(raw("open",package)))
            self.assertFalse(self.blocked.accepts(raw("open",package)))
            self.assertTrue(self.changed.accepts(raw("open",package)))
            self.assertFalse(self.returned.accepts(raw("open",package)))
        self.assertTrue(self.blocked.accepts(raw("open","com.example.other")))
        self.assertFalse(self.blocked.accepts(raw("open","com.example.unlisted")))
    def test_other_tools_and_type_payloads_are_not_broadened_or_selected(self):
        for text in ("first","second"):
            self.assertTrue(self.blocked.accepts(raw("type",node_label="same label",node_id="n1",text=text)))
        for action in ("back","home"):
            self.assertTrue(self.blocked.accepts(raw(action)))
        self.assertTrue(self.blocked.accepts(raw("wait",duration_ms=100)))
        self.assertTrue(self.blocked.accepts(raw("done",status="partial",summary="not complete")))
        self.assertFalse(self.blocked.accepts(raw("done",status="success")))
    def test_original_observation_and_exact_label_pairs_remain_bound(self):
        sample=raw("click",node_label="different",node_id="n3")
        self.assertFalse(self.blocked.accepts(sample.replace(OBS,"0"*32)))
        self.assertFalse(self.blocked.accepts(sample.replace(PKG,"com.example.foreign")))
        self.assertFalse(self.blocked.accepts(raw("click",x=1,y=1)))
if __name__=="__main__":unittest.main(verbosity=2)
