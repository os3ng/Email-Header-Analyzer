import unittest
from pathlib import Path
from analyzer import analyze_email_headers
from brand_detector import detect_brand_spoofing

SAMPLES = Path(__file__).parent / "samples"


class TestAnalyzer(unittest.TestCase):
    def test_suspicious_sample(self):
        result = analyze_email_headers((SAMPLES / "suspicious.eml").read_bytes())
        self.assertEqual(result["checks"]["DMARC"], "fail")
        self.assertEqual(result["verdict"], "High risk indicators")
        self.assertEqual(result["score"], 100)

    def test_normal_sample(self):
        result = analyze_email_headers((SAMPLES / "normal.eml").read_bytes())
        self.assertEqual(result["checks"]["DMARC"], "pass")
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["verdict"], "Low risk indicators found")

    def test_typo_is_detected_even_with_dmarc_pass(self):
        sample = (SAMPLES / "maybank-lookalike.eml").read_bytes()
        result = analyze_email_headers(sample)
        self.assertEqual(result["checks"]["DMARC"], "pass")
        self.assertEqual(result["verdict"], "High risk indicators")
        self.assertTrue(result["brand_findings"])
        self.assertIn("typosquatting", result["brand_findings"][0]["finding"])

    def test_fake_subdomain_is_not_trusted(self):
        findings = detect_brand_spoofing('Maybank <notice@maybank2u.com.my.fake.example>')
        self.assertTrue(findings)
        self.assertIn("embedded", findings[0]["finding"])

    def test_lookalike_unicode_is_detected(self):
        # The character after 'b' is Cyrillic a (U+0430), not Latin a.
        findings = detect_brand_spoofing('Maybank <alert@maybаnk2u.com.my>')
        self.assertTrue(findings)
        self.assertIn('Unicode', findings[0]['finding'])

    def test_display_name_spoof(self):
        findings = detect_brand_spoofing('Maybank Security <alerts@another.example>')
        self.assertTrue(findings)
        self.assertIn('Display name', findings[0]['finding'])

    def test_reference_domain_is_not_flagged_as_lookalike(self):
        findings = detect_brand_spoofing('Maybank <alerts@maybank2u.com.my>')
        self.assertEqual(findings, [])
        findings = detect_brand_spoofing('Maybank <alerts@mail.maybank2u.com.my>')
        self.assertEqual(findings, [])

    def test_missing_auth_is_not_called_safe(self):
        result = analyze_email_headers(b"From: A <a@example.org>\nSubject: Hello\n\n")
        self.assertEqual(result["verdict"], "Insufficient authentication data")


if __name__ == "__main__":
    unittest.main()
