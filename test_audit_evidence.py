import hashlib
import tempfile
from pathlib import Path
from datetime import date
import unittest
from audit_evidence import evaluate


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / 'review.txt').write_bytes(b'approved review')
        self.control = {'id': 'ACCESS', 'owner': 'IAM', 'applicable': True, 'max_age_days': 30,
                        'evidence': [{'path': 'review.txt', 'collected_on': '2026-06-01', 'sha256': hashlib.sha256(b'approved review').hexdigest()}]}

    def report(self):
        return evaluate({'schema': 'audit-evidence/v1', 'controls': [self.control]}, self.root, date(2026, 6, 30))['controls'][0]

    def test_ready_is_not_compliant(self):
        self.assertEqual(self.report()['status'], 'ready_for_review')

    def test_stale_and_tampered(self):
        self.control['evidence'][0]['collected_on'] = '2026-01-01'
        (self.root / 'review.txt').write_bytes(b'tampered')
        self.assertEqual(set(self.report()['issues']), {'stale_evidence:review.txt', 'hash_mismatch:review.txt'})

    def test_missing_and_future(self):
        (self.root / 'review.txt').unlink()
        self.control['evidence'][0]['collected_on'] = '2027-01-01'
        self.assertEqual(set(self.report()['issues']), {'missing_artifact:review.txt', 'future_evidence:review.txt'})

    def test_exclusion_needs_reason(self):
        self.control['applicable'] = False
        self.assertIn('unjustified_exclusion', self.report()['issues'])
        self.control['exclusion_reason'] = 'Reviewed and approved rationale'
        self.assertEqual(self.report()['status'], 'excluded')

    def test_path_traversal_fails(self):
        self.control['evidence'][0]['path'] = '../secret'
        with self.assertRaises(ValueError):
            self.report()

    def test_duplicate_ids_fail(self):
        with self.assertRaises(ValueError):
            evaluate({'schema': 'audit-evidence/v1', 'controls': [self.control, self.control]}, self.root, date(2026, 6, 30))


if __name__ == '__main__':
    unittest.main()
