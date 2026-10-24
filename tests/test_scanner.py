#!/usr/bin/env python3
"""
Unit Test Suite for Automated Web Security Scanner
==================================================
Project: IBM SkillsBuild Cybersecurity Bootcamp
"""

import unittest
from scanner import HeaderAuditor, CORSAuditor, WebScanner, Severity, HeaderFinding

class TestHeaderAuditor(unittest.TestCase):

    def test_missing_all_security_headers(self):
        empty_headers = {}
        findings, score = HeaderAuditor.audit(empty_headers, "https://test.example.com")
        
        # Missing CSP, HSTS, XFO, XCTO should result in low score
        self.assertLess(score, 50)
        headers_found = {f.header: f for f in findings}
        self.assertIn("Content-Security-Policy", headers_found)
        self.assertEqual(headers_found["Content-Security-Policy"].status, "FAIL")
        self.assertIn("Strict-Transport-Security", headers_found)
        self.assertEqual(headers_found["Strict-Transport-Security"].status, "FAIL")
        self.assertIn("X-Frame-Options", headers_found)
        self.assertEqual(headers_found["X-Frame-Options"].status, "FAIL")
        self.assertIn("X-Content-Type-Options", headers_found)
        self.assertEqual(headers_found["X-Content-Type-Options"].status, "FAIL")

    def test_strong_security_headers(self):
        secure_headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
            "Cross-Origin-Opener-Policy": "same-origin"
        }
        findings, score = HeaderAuditor.audit(secure_headers, "https://secure.example.com")
        self.assertGreaterEqual(score, 95)
        for f in findings:
            if f.header in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options", "X-Content-Type-Options"]:
                self.assertEqual(f.status, "PASS")

    def test_weak_csp_warning(self):
        weak_csp_headers = {
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "SAMEORIGIN",
            "X-Content-Type-Options": "nosniff"
        }
        findings, score = HeaderAuditor.audit(weak_csp_headers, "https://test.example.com")
        csp_finding = next(f for f in findings if f.header == "Content-Security-Policy")
        self.assertEqual(csp_finding.status, "WARN")
        self.assertIn("unsafe-inline", csp_finding.description)

    def test_information_leakage_detection(self):
        leaky_headers = {
            "Server": "Apache/2.4.49 (Unix) OpenSSL/1.1.1l",
            "X-Powered-By": "PHP/7.4.21",
            "X-AspNet-Version": "4.0.30319"
        }
        findings, score = HeaderAuditor.audit(leaky_headers, "https://leaky.example.com")
        leak_finding = next((f for f in findings if f.header == "Information Leakage"), None)
        self.assertIsNotNone(leak_finding)
        self.assertEqual(leak_finding.status, "FAIL")
        self.assertIn("PHP/7.4.21", leak_finding.value)

class TestScannerScoring(unittest.TestCase):

    def test_grade_calculation(self):
        self.assertEqual(WebScanner._calculate_grade(100), "A+")
        self.assertEqual(WebScanner._calculate_grade(96), "A+")
        self.assertEqual(WebScanner._calculate_grade(88), "A")
        self.assertEqual(WebScanner._calculate_grade(78), "B")
        self.assertEqual(WebScanner._calculate_grade(65), "C")
        self.assertEqual(WebScanner._calculate_grade(50), "D")
        self.assertEqual(WebScanner._calculate_grade(30), "F")

if __name__ == "__main__":
    unittest.main()
