import copy
import json
import re
import sys
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'tools'))
from build import load_rules, load_attack, artifacts, spl
from evaluate import evaluate

START=1800000000

class RulesTest(unittest.TestCase):
    def setUp(self):
        self.rules=load_rules()

    def positive(self,r):
        fixtures=json.loads((ROOT/f'tests/fixtures/{r["id"]}.json').read_text(encoding='utf-8'))
        return next(f['events'] for f in fixtures if f['name']=='positive')

    def detect(self,r,events):
        return evaluate(r,events,START,START+300)

    def test_schema(self):
        self.assertGreaterEqual(len(self.rules),10)
        self.assertEqual(len({r['id'] for r in self.rules}),len(self.rules))
        for r in self.rules:
            with self.subTest(rule=r['id']):
                self.assertRegex(r['attack_id'],r'^T\d{4}(\.\d{3})?$')
                self.assertIn(r['log_source'],['windows','fw','proxy','ndr'])
                self.assertIn(r['status'],['experimental','validated','deprecated'])
                self.assertEqual(r['window_seconds'],300)
                self.assertGreaterEqual(r['threshold'],1)
                for field in ['title','false_positives','triage','prerequisites','limitations','references','provenance']:
                    self.assertTrue(r[field])
                needed=set(r['group_by'])|{'_time','log_type'}
                for field,op,value in r['conditions']:
                    self.assertRegex(field,r'^[A-Za-z_][A-Za-z0-9_]*$')
                    self.assertIn(op,['=','~='])
                    needed.add(field)
                    if op=='~=': re.compile(value)
                if r['metric']!='count': needed.add(r['metric'])
                self.assertEqual(set(r['required_fields']),needed)

    def test_fixtures(self):
        for r in self.rules:
            fs=json.loads((ROOT/f'tests/fixtures/{r["id"]}.json').read_text(encoding='utf-8'))
            self.assertTrue(any(f['expected'] for f in fs))
            self.assertTrue(any(not f['expected'] for f in fs))
            for f in fs:
                with self.subTest(rule=r['id'],fixture=f['name']):
                    self.assertEqual(self.detect(r,f['events']),f['expected'])

    def test_missing_and_null_fields(self):
        for r in self.rules:
            for field in r['required_fields']:
                for null in [False,True]:
                    with self.subTest(rule=r['id'],field=field,null=null):
                        events=copy.deepcopy(self.positive(r))
                        for e in events:
                            if null: e[field]=None
                            else: e.pop(field)
                        self.assertFalse(self.detect(r,events))

    def test_log_isolation(self):
        for r in self.rules:
            es=copy.deepcopy(self.positive(r))
            for e in es: e['log_type']='unrelated'
            self.assertFalse(self.detect(r,es))

    def test_window_boundaries(self):
        for r in self.rules:
            for timestamp,want in [(START-1,False),(START,True),(START+299,True),(START+300,False)]:
                with self.subTest(rule=r['id'],timestamp=timestamp):
                    es=copy.deepcopy(self.positive(r))
                    for e in es: e['_time']=timestamp
                    self.assertEqual(self.detect(r,es),want)
            with self.assertRaises(ValueError): evaluate(r,[],START,START+600)

    def test_threshold_and_group_isolation(self):
        for r in self.rules:
            if r['threshold']<=1: continue
            with self.subTest(rule=r['id']):
                es=copy.deepcopy(self.positive(r))
                self.assertFalse(self.detect(r,es[:-1]))
                es[-1][r['group_by'][0]]='another-host'
                self.assertFalse(self.detect(r,es))
                if r['metric']!='count':
                    es=copy.deepcopy(self.positive(r))
                    for e in es: e[r['metric']]=es[0][r['metric']]
                    self.assertFalse(self.detect(r,es))

    def test_generated_artifacts_current(self):
        for path,content in artifacts(self.rules).items():
            with self.subTest(path=path):
                self.assertEqual((ROOT/path).read_text(encoding='utf-8'),content)

    def test_attack_positions_and_references(self):
        attack=load_attack()
        for r in self.rules:
            with self.subTest(rule=r['id']):
                tech=attack['techniques'][r['attack_id']]
                self.assertEqual(set(r['attack_tactics']),set(tech['tactics']))
                self.assertIn(r['tactic'],r['attack_tactics'])
                self.assertIn(r['attack_id'].split('.')[0],attack['techniques'])
                self.assertGreaterEqual(len(r['triage']),5)
                self.assertGreaterEqual(len(r['limitations']),4)
                for ref in r['references']:
                    for key in ['title','url','summary','accessed']: self.assertTrue(ref[key])
                card=(ROOT/f'docs/rules/{r["id"]}.md').read_text(encoding='utf-8')
                self.assertIn('```spl\n'+spl(r)+'```',card)
                self.assertNotIn('queries/',card)

    def test_symbol_evaluation(self):
        r=next(r for r in self.rules if r['id']=='WIN-001')
        es=copy.deepcopy(self.positive(r))
        es[0]['command_line']='powershell -ENC SQBFAFgA'
        self.assertTrue(self.detect(r,es))
        es[0]['process_path']='C:\\Windows\\notpowershell.exe'
        self.assertFalse(self.detect(r,es))

if __name__=='__main__': unittest.main()
