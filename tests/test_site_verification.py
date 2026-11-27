"""Hermetic tests for DNS alternatives, subpage checks, and descriptions."""
import os
import sys
import unittest
from unittest import mock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from analyzer import domain_checker
from analyzer.link_crawler import inspect_subpages
from analyzer.site_describer import describe_site


DNS_OK = {"resolves": True, "blocked": False, "records": {"A": ["93.184.216.34"]}, "addresses": []}
TLS_PAGE = {"reachable": True, "blocked": False, "url": "https://netgame.com/", "redirects": 0,
            "tls_valid": True, "status_code": 200, "content_type": "text/html", "body": "<title>Netgame</title>"}


class TestDomainVerification(unittest.TestCase):
    def test_nonexistent_netgame_edu_suggests_verified_netgame_com(self):
        def resolve(host):
            return ({"resolves": False, "blocked": False, "records": {}, "addresses": [],
                     "error": "NXDOMAIN"} if host == "netgame.edu" else DNS_OK)

        with mock.patch.object(domain_checker, "resolve_host", side_effect=resolve), \
             mock.patch.object(domain_checker, "load_tranco_ranks", return_value={"netgame.com": 12345}), \
             mock.patch.object(domain_checker, "_checked_request", return_value=TLS_PAGE), \
             mock.patch.object(domain_checker, "domain_age_days", return_value=365):
            result = domain_checker.check_domain("netgame.edu")
        self.assertEqual(result["status"], "does_not_resolve")
        self.assertTrue(result["suggestions"])
        self.assertEqual(result["suggestions"][0]["domain"], "netgame.com")
        self.assertTrue(result["suggestions"][0]["verified_genuine"])

    def test_unreachable_domain_does_not_claim_site_description(self):
        with mock.patch.object(domain_checker, "resolve_host", return_value=DNS_OK), \
             mock.patch.object(domain_checker, "_checked_request", return_value={
                 "reachable": False, "blocked": False, "url": "https://example.com/",
                 "error": "The website timed out.", "status_code": None, "tls_valid": False,
             }), mock.patch.object(domain_checker, "load_tranco_ranks", return_value={}):
            checked = domain_checker.check_domain("example.com")
        result = describe_site(None, "https://example.com/", reachable=False)
        self.assertEqual(checked["status"], "exists")
        self.assertFalse(checked["http"]["reachable"])
        self.assertFalse(result["available"])
        self.assertIn("unreachable", result["description"].lower())

    def test_tranco_absence_never_marks_candidate_genuine(self):
        with mock.patch.object(domain_checker, "load_tranco_ranks", return_value={}):
            evidence = domain_checker._evidence("netgame.com", TLS_PAGE)
        self.assertFalse(evidence["verified_genuine"])
        self.assertEqual(evidence["confidence"], "low")

    def test_typosquat_suggests_close_tranco_domain(self):
        with mock.patch.object(domain_checker, "resolve_host", return_value=DNS_OK), \
             mock.patch.object(domain_checker, "load_tranco_ranks", return_value={"paypal.com": 12}), \
             mock.patch.object(domain_checker, "_checked_request", return_value={**TLS_PAGE, "url": "https://paypal.com/"}), \
             mock.patch.object(domain_checker, "domain_age_days", return_value=500):
            result = domain_checker.check_domain("paypa1.com")
        self.assertEqual(result["status"], "exists")
        self.assertTrue(any(item["domain"] == "paypal.com" for item in result["suggestions"]))


class TestSubpageVerification(unittest.TestCase):
    def setUp(self):
        self.safe_page = {"reachable": True, "blocked": False, "url": "https://shop.example.com/login",
                          "redirects": 0, "tls_valid": True, "status_code": 200,
                          "content_type": "text/html", "body": "<title>Login</title><h1>Sign in</h1>"}

    def test_verified_parent_and_safe_internal_subpage(self):
        homepage = '<a href="/login">Login</a>'
        with mock.patch("analyzer.link_crawler._robots_policy", return_value=None), \
             mock.patch("analyzer.link_crawler._checked_request", return_value=self.safe_page), \
             mock.patch("analyzer.link_crawler.RiskExplainer.analyze_url",
                        return_value={"unified_verdict": "Likely safe", "hybrid_risk_score": 12}):
            result = inspect_subpages("https://shop.example.com/", "example.com", True, homepage)
        self.assertEqual(result["verified_count"], 1)
        self.assertEqual(result["links"][0]["verdict"], "Genuine")

    def test_form_posting_to_another_domain_is_flagged(self):
        html = '<form action="https://collect.evil.example.net/submit"><input type="password"></form>'
        page = {**self.safe_page, "body": html}
        with mock.patch("analyzer.link_crawler._robots_policy", return_value=None), \
             mock.patch("analyzer.link_crawler._checked_request", return_value=page), \
             mock.patch("analyzer.link_crawler.RiskExplainer.analyze_url",
                        return_value={"unified_verdict": "Likely safe", "hybrid_risk_score": 10}):
            result = inspect_subpages("https://shop.example.com/", "example.com", True,
                                      '<a href="/login">Login</a>')
        self.assertIn(result["links"][0]["verdict"], {"Phishing", "Suspicious"})
        self.assertEqual(result["links"][0]["red_flags"][0]["code"], "cross_domain_form")

    def test_external_payment_gateway_is_third_party(self):
        homepage = '<a href="https://checkout.stripe.com/pay/abc">Checkout</a>'
        with mock.patch("analyzer.link_crawler._robots_policy", return_value=None):
            result = inspect_subpages("https://shop.example.com/", "example.com", True, homepage)
        self.assertEqual(result["links"][0]["verdict"], "Third-party")
        self.assertFalse(result["links"][0]["same_registered_domain"])

    def test_unreachable_subpage_is_not_genuine(self):
        failed = {"reachable": False, "blocked": False, "url": "https://shop.example.com/login",
                  "error": "timeout", "status_code": None, "tls_valid": False}
        with mock.patch("analyzer.link_crawler._robots_policy", return_value=None), \
             mock.patch("analyzer.link_crawler._checked_request", return_value=failed):
            result = inspect_subpages("https://shop.example.com/", "example.com", True,
                                      '<a href="/login">Login</a>')
        self.assertEqual(result["links"][0]["verdict"], "Unreachable")

    def test_parent_failure_prevents_genuine_subpage_claims(self):
        result = inspect_subpages("https://shop.example.com/", "example.com", False,
                                  '<a href="/login">Login</a>')
        self.assertFalse(result["enabled"])
        self.assertEqual(result["total_count"], 0)


if __name__ == "__main__":
    unittest.main()

def test_description_explains_service_from_submitted_page():
    parsed = domain_checker.parse_user_input("https://example.org/tools/search?q=books#results")
    assert parsed["normalized_url"] == "https://example.org/tools/search?q=books"
    page = ('<meta name="description" content="Welcome to our official website.">'
            '<main><p>This library helps students find and borrow textbooks.</p></main>')
    assert describe_site(page, parsed["normalized_url"])["description"] == (
        "This library helps students find and borrow textbooks.")


def test_project_csv_uses_only_ranked_tranco_rows(tmp_path, monkeypatch):
    path = tmp_path / "raw.csv"
    path.write_text("hostname,label,source,tranco_rank\n"
                    "one.example,0,tranco,123.0\n"
                    "two.example,1,phishtank,12\n"
                    "three.example,0,tranco,\n")
    monkeypatch.setenv("TRANCO_CSV_PATH", str(path))
    assert domain_checker.load_tranco_ranks() == {"one.example": 123}


def test_visible_description_without_paragraph_tags():
    result = describe_site("<main><div>Search and compare library collections.</div></main>", None)
    assert result["description"] == "Search and compare library collections."
