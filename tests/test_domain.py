import sys
import unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'app'))
from domain import normalize_target, decision, snapshot, parse_json, dump, like_pattern
from datetime import datetime
class DomainTests(unittest.TestCase):
    def test_normalization(self):
        self.assertEqual(normalize_target('DOMAIN',' Docs.Example.TEST. '),'docs.example.test')
        self.assertEqual(normalize_target('IPV4','192.0.2.10'),'192.0.2.10')
    def test_invalid(self):
        for kind, val in [('DOMAIN','https://example.test'),('DOMAIN','*.example.test'),('DOMAIN','example..test'),('DOMAIN','-bad.test'),('DOMAIN','192.0.2.10'),('DOMAIN','tên.test'),('IPV4','192.0.2.0/24'),('IPV4','256.0.0.1'),('IPV4','::1')]:
            with self.subTest(kind=kind,val=val), self.assertRaises(ValueError): normalize_target(kind,val)
    def test_priority(self):
        w={'list_type':'WHITELIST'}; b={'list_type':'BLACKLIST'}
        self.assertEqual(decision([])[0],'BLOCK')
        self.assertEqual(decision([w])[0],'ALLOW')
        self.assertEqual(decision([b])[0],'BLOCK')
        self.assertEqual(decision([w,b])[0],'BLOCK')
    def test_snapshot(self):
        obj={'created_at':datetime(2026,11,25,12,0),'version_no':1}
        self.assertEqual(snapshot(obj),parse_json(dump(obj)))
        self.assertIsNone(snapshot(None))
    def test_like_pattern(self):
        self.assertEqual(like_pattern('  Docs.Example  ', str.lower), '%docs.example%')
        self.assertEqual(like_pattern('req-100%_a\\b', str.upper), r'%REQ-100\%\_A\\B%')
if __name__=='__main__':unittest.main()
