import tempfile
import unittest
from pathlib import Path

from securescope import scan, summary


class SecureScopeTests(unittest.TestCase):
    def test_detects_and_redacts_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('api_key = "abcdef123456"\nDEBUG = True\n', encoding="utf-8")
            findings = scan(root)
            self.assertEqual({f.rule_id for f in findings}, {"SS001", "SS002"})
            secret = next(f for f in findings if f.rule_id == "SS002")
            self.assertNotIn("abcdef123456", secret.evidence)

    def test_summary_counts_stride_and_severity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text('exec(user_input)\n', encoding="utf-8")
            result = summary(scan(root))
            self.assertEqual(result["total_findings"], 1)
            self.assertEqual(result["by_stride"]["Tampering"], 1)


if __name__ == "__main__":
    unittest.main()
