"""
tests/test_checker.py — Unit tests for dsgvo-compliance-checker.

Run with: python3 -m pytest tests/ -v
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import tempfile
from unittest.mock import MagicMock, patch
from bs4 import BeautifulSoup

from checker.checks import (
    ScanContext, check_https, check_privacy_policy, check_imprint,
    check_cookie_banner, check_trackers, check_security_headers,
    check_hsts, check_forms_https
)
from checker.scanner import ScanResult
from checker.report import generate_html_report


def make_ctx(html="", headers=None, url="https://example.com", response_url=None):
    return ScanContext(
        url=url,
        html=html,
        headers=headers or {},
        soup=BeautifulSoup(html, "html.parser"),
        response_url=response_url or url,
    )


# ── HTTPS checks ──────────────────────────────────────────────────────────────

class TestHTTPS:
    def test_https_passes(self):
        ctx = make_ctx(response_url="https://example.com")
        assert check_https(ctx).passed is True

    def test_http_fails(self):
        ctx = make_ctx(response_url="http://example.com")
        assert check_https(ctx).passed is False

    def test_http_is_critical(self):
        ctx = make_ctx(response_url="http://example.com")
        assert check_https(ctx).severity == "critical"


# ── Privacy policy checks ─────────────────────────────────────────────────────

class TestPrivacyPolicy:
    def test_detects_privacy_link(self):
        html = '<a href="/privacy">Privacy Policy</a>'
        assert check_privacy_policy(make_ctx(html)).passed is True

    def test_detects_datenschutz_link(self):
        html = '<a href="/datenschutz">Datenschutz</a>'
        assert check_privacy_policy(make_ctx(html)).passed is True

    def test_fails_without_link(self):
        html = '<p>No privacy link here</p>'
        assert check_privacy_policy(make_ctx(html)).passed is False

    def test_detects_href_keyword(self):
        html = '<a href="/privacy-policy">More info</a>'
        assert check_privacy_policy(make_ctx(html)).passed is True


# ── Imprint checks ────────────────────────────────────────────────────────────

class TestImprint:
    def test_detects_impressum(self):
        html = '<a href="/impressum">Impressum</a>'
        assert check_imprint(make_ctx(html)).passed is True

    def test_detects_imprint(self):
        html = '<a href="/imprint">Legal</a>'
        assert check_imprint(make_ctx(html)).passed is True

    def test_fails_without_imprint(self):
        html = '<p>Nothing here</p>'
        assert check_imprint(make_ctx(html)).passed is False

    def test_is_warning_not_critical(self):
        html = '<p>Nothing here</p>'
        assert check_imprint(make_ctx(html)).severity == "warning"


# ── Cookie banner checks ──────────────────────────────────────────────────────

class TestCookieBanner:
    def test_detects_cookiebanner_class(self):
        html = '<div class="cookiebanner">Accept cookies</div>'
        assert check_cookie_banner(make_ctx(html)).passed is True

    def test_detects_cookiebot(self):
        html = '<script src="https://consent.cookiebot.com/uc.js"></script>'
        assert check_cookie_banner(make_ctx(html)).passed is True

    def test_detects_keywords(self):
        html = '<p>We use cookies. Please accept our cookie policy.</p>'
        assert check_cookie_banner(make_ctx(html)).passed is True

    def test_fails_without_banner(self):
        html = '<p>Welcome to our site</p>'
        assert check_cookie_banner(make_ctx(html)).passed is False


# ── Tracker checks ────────────────────────────────────────────────────────────

class TestTrackers:
    def test_detects_google_analytics(self):
        html = '<script src="https://www.google-analytics.com/analytics.js"></script>'
        result = check_trackers(make_ctx(html))
        assert result.passed is False
        assert len(result.found_items) > 0

    def test_detects_facebook_pixel(self):
        html = '<script>fbq("track", "PageView"); connect.facebook.net</script>'
        result = check_trackers(make_ctx(html))
        assert result.passed is False

    def test_passes_without_trackers(self):
        html = '<script src="/local/script.js"></script>'
        assert check_trackers(make_ctx(html)).passed is True

    def test_critical_when_trackers_found(self):
        html = '<script src="https://www.google-analytics.com/ga.js"></script>'
        assert check_trackers(make_ctx(html)).severity == "critical"


# ── Security header checks ────────────────────────────────────────────────────

class TestSecurityHeaders:
    def test_passes_with_all_headers(self):
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()",
        }
        assert check_security_headers(make_ctx(headers=headers)).passed is True

    def test_fails_with_missing_headers(self):
        assert check_security_headers(make_ctx(headers={})).passed is False

    def test_missing_headers_in_found_items(self):
        result = check_security_headers(make_ctx(headers={}))
        assert len(result.found_items) > 0


# ── HSTS checks ───────────────────────────────────────────────────────────────

class TestHSTS:
    def test_passes_with_hsts(self):
        headers = {"Strict-Transport-Security": "max-age=31536000"}
        assert check_hsts(make_ctx(headers=headers)).passed is True

    def test_fails_without_hsts(self):
        assert check_hsts(make_ctx(headers={})).passed is False


# ── Secure form checks ────────────────────────────────────────────────────────

class TestSecureForms:
    def test_passes_with_https_form(self):
        html = '<form action="https://example.com/submit"></form>'
        assert check_forms_https(make_ctx(html)).passed is True

    def test_fails_with_http_form(self):
        html = '<form action="http://example.com/submit"></form>'
        result = check_forms_https(make_ctx(html))
        assert result.passed is False
        assert len(result.found_items) > 0

    def test_passes_with_relative_action(self):
        html = '<form action="/submit"></form>'
        assert check_forms_https(make_ctx(html)).passed is True


# ── ScanResult scoring ────────────────────────────────────────────────────────

class TestScanResultScoring:
    def _make_result(self, passed_count, total_count):
        from checker.checks import CheckResult
        checks = []
        for i in range(total_count):
            checks.append(CheckResult(
                name=f"Check {i}",
                passed=(i < passed_count),
                severity="warning",
                detail="",
                recommendation="",
            ))
        return ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            scanned_at="2026-04-28T00:00:00",
            duration_seconds=1.0,
            checks=checks,
        )

    def test_perfect_score(self):
        assert self._make_result(8, 8).score == 100

    def test_zero_score(self):
        assert self._make_result(0, 8).score == 0

    def test_rating_a(self):
        assert self._make_result(8, 8).rating == "A"

    def test_rating_f(self):
        assert self._make_result(0, 8).rating == "F"


# ── Report generation ─────────────────────────────────────────────────────────

class TestReportGeneration:
    def _make_scan_result(self):
        from checker.checks import CheckResult
        checks = [
            CheckResult("HTTPS", True, "critical", "OK", "", "Art. 32 DSGVO"),
            CheckResult("Trackers", False, "critical", "Found: google-analytics.com", "Remove trackers", "Art. 6 DSGVO", ["google-analytics.com"]),
        ]
        return ScanResult(
            url="https://example.com",
            final_url="https://example.com",
            scanned_at="2026-04-28T00:00:00",
            duration_seconds=1.5,
            checks=checks,
        )

    def test_creates_html_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_scan_result(), out)
            assert out.exists()

    def test_report_contains_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_scan_result(), out)
            assert "example.com" in out.read_text()

    def test_report_contains_gdpr_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_scan_result(), out)
            assert "DSGVO" in out.read_text()

    def test_report_contains_tracker_finding(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "report.html"
            generate_html_report(self._make_scan_result(), out)
            assert "google-analytics.com" in out.read_text()
