"""
checks.py — Individual DSGVO/GDPR compliance checks.

Each check receives a ScanContext and returns a CheckResult.
"""

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

TRACKER_FILE = Path(__file__).parent / "trackers.txt"


@dataclass
class CheckResult:
    name: str
    passed: bool
    severity: str          # "critical" | "warning" | "info"
    detail: str
    recommendation: str
    gdpr_reference: str = ""
    found_items: list = field(default_factory=list)


@dataclass
class ScanContext:
    url: str
    html: str
    headers: dict
    soup: BeautifulSoup
    response_url: str      # final URL after redirects


def _load_trackers() -> list[str]:
    if not TRACKER_FILE.exists():
        return []
    lines = TRACKER_FILE.read_text(encoding="utf-8").splitlines()
    return [l.strip() for l in lines if l.strip() and not l.startswith("#")]


# ── Individual checks ─────────────────────────────────────────────────────────

def check_https(ctx: ScanContext) -> CheckResult:
    uses_https = ctx.response_url.startswith("https://")
    return CheckResult(
        name="HTTPS Encryption",
        passed=uses_https,
        severity="critical",
        detail="Site is served over HTTPS." if uses_https else "Site is NOT served over HTTPS.",
        recommendation="" if uses_https else "Enable HTTPS with a valid TLS certificate. HTTP transmits data in plaintext.",
        gdpr_reference="Art. 32 DSGVO — Technical security measures",
    )


def check_privacy_policy(ctx: ScanContext) -> CheckResult:
    keywords = [
        "datenschutz", "privacy policy", "datenschutzerklärung",
        "privacy", "privacybeleid", "политика конфиденциальности"
    ]
    links = ctx.soup.find_all("a", href=True)
    found = []
    for link in links:
        text = (link.get_text() or "").lower()
        href = (link.get("href") or "").lower()
        if any(kw in text or kw in href for kw in keywords):
            found.append(urljoin(ctx.url, link["href"]))

    passed = len(found) > 0
    return CheckResult(
        name="Privacy Policy",
        passed=passed,
        severity="critical",
        detail=f"Privacy policy link found: {found[0]}" if passed else "No privacy policy link detected.",
        recommendation="" if passed else "Add a clearly visible link to your privacy policy on every page.",
        gdpr_reference="Art. 13/14 DSGVO — Information obligations",
        found_items=found[:3],
    )


def check_imprint(ctx: ScanContext) -> CheckResult:
    """Impressum check — required for German websites."""
    keywords = ["impressum", "imprint", "legal notice", "about us", "kontakt"]
    links = ctx.soup.find_all("a", href=True)
    found = []
    for link in links:
        text = (link.get_text() or "").lower()
        href = (link.get("href") or "").lower()
        if any(kw in text or kw in href for kw in keywords):
            found.append(urljoin(ctx.url, link["href"]))

    passed = len(found) > 0
    return CheckResult(
        name="Imprint (Impressum)",
        passed=passed,
        severity="warning",
        detail=f"Imprint link found: {found[0]}" if passed else "No imprint link detected.",
        recommendation="" if passed else "German law (§5 TMG) requires an imprint on all commercial websites.",
        gdpr_reference="§5 TMG (German Telemedia Act)",
        found_items=found[:3],
    )


def check_cookie_banner(ctx: ScanContext) -> CheckResult:
    keywords = [
        "cookie", "einwilligung", "consent", "akzeptieren", "accept",
        "zustimmen", "ablehnen", "decline", "gdpr", "dsgvo",
        "we use cookies", "wir verwenden cookies"
    ]
    html_lower = ctx.html.lower()
    found_keywords = [kw for kw in keywords if kw in html_lower]

    # Also check for common cookie banner IDs/classes
    banner_patterns = [
        "cookiebanner", "cookie-banner", "cookie-consent", "cookieconsent",
        "cookie-notice", "gdpr-banner", "consent-banner", "CookieConsent",
        "onetrust", "cookiebot", "usercentrics", "klaro"
    ]
    found_patterns = []
    for pattern in banner_patterns:
        if pattern.lower() in ctx.html.lower():
            found_patterns.append(pattern)

    passed = len(found_keywords) >= 2 or len(found_patterns) > 0
    detail_parts = []
    if found_patterns:
        detail_parts.append(f"Cookie framework detected: {', '.join(found_patterns)}")
    if found_keywords:
        detail_parts.append(f"Consent keywords found: {', '.join(found_keywords[:5])}")

    return CheckResult(
        name="Cookie Consent Banner",
        passed=passed,
        severity="critical",
        detail=" | ".join(detail_parts) if detail_parts else "No cookie consent mechanism detected.",
        recommendation="" if passed else "Implement a DSGVO-compliant cookie consent solution before setting non-essential cookies.",
        gdpr_reference="Art. 6 DSGVO + §25 TTDSG — Consent for cookies",
        found_items=found_patterns,
    )


def check_trackers(ctx: ScanContext) -> CheckResult:
    tracker_domains = _load_trackers()
    html_lower = ctx.html.lower()
    scripts = ctx.soup.find_all("script", src=True)
    script_srcs = [s.get("src", "") for s in scripts]

    found_trackers = []
    for tracker in tracker_domains:
        tracker_lower = tracker.lower()
        if tracker_lower in html_lower:
            found_trackers.append(tracker)
        elif any(tracker_lower in src.lower() for src in script_srcs):
            if tracker not in found_trackers:
                found_trackers.append(tracker)

    found_trackers = list(set(found_trackers))
    passed = len(found_trackers) == 0

    return CheckResult(
        name="Third-Party Trackers",
        passed=passed,
        severity="critical" if found_trackers else "info",
        detail=f"No third-party trackers detected." if passed else f"{len(found_trackers)} tracker(s) found: {', '.join(found_trackers)}",
        recommendation="" if passed else "Ensure consent is obtained before loading tracking scripts. Consider server-side tagging or consent-gated loading.",
        gdpr_reference="Art. 6 DSGVO — Lawful basis for processing",
        found_items=found_trackers,
    )


def check_security_headers(ctx: ScanContext) -> CheckResult:
    headers = {k.lower(): v for k, v in ctx.headers.items()}
    required = {
        "x-content-type-options": "Prevents MIME-type sniffing attacks",
        "x-frame-options": "Prevents clickjacking attacks",
        "content-security-policy": "Controls resource loading, mitigates XSS",
        "referrer-policy": "Controls referrer information sent with requests",
        "permissions-policy": "Controls browser feature access",
    }
    missing = []
    present = []
    for header, description in required.items():
        if header in headers:
            present.append(f"{header}: {headers[header][:60]}")
        else:
            missing.append(f"{header} ({description})")

    passed = len(missing) == 0
    return CheckResult(
        name="Security Headers",
        passed=passed,
        severity="warning",
        detail=f"{len(present)}/{len(required)} recommended headers present." + (f" Missing: {', '.join([m.split(' (')[0] for m in missing])}" if missing else ""),
        recommendation="" if passed else f"Add missing headers: {'; '.join(missing[:3])}",
        gdpr_reference="Art. 32 DSGVO — Technical security measures",
        found_items=missing,
    )


def check_hsts(ctx: ScanContext) -> CheckResult:
    headers = {k.lower(): v for k, v in ctx.headers.items()}
    hsts = headers.get("strict-transport-security", "")
    passed = bool(hsts)
    return CheckResult(
        name="HSTS (HTTP Strict Transport Security)",
        passed=passed,
        severity="warning",
        detail=f"HSTS header present: {hsts}" if passed else "HSTS header not found.",
        recommendation="" if passed else "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to enforce HTTPS.",
        gdpr_reference="Art. 32 DSGVO — Integrity and confidentiality",
    )


def check_forms_https(ctx: ScanContext) -> CheckResult:
    forms = ctx.soup.find_all("form")
    insecure_forms = []
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http://"):
            insecure_forms.append(action)

    passed = len(insecure_forms) == 0
    return CheckResult(
        name="Secure Form Submission",
        passed=passed,
        severity="critical" if insecure_forms else "info",
        detail=f"All forms submit over HTTPS." if passed else f"{len(insecure_forms)} form(s) submit over HTTP: {', '.join(insecure_forms)}",
        recommendation="" if passed else "All form action URLs must use HTTPS to protect submitted data.",
        gdpr_reference="Art. 32 DSGVO — Security of processing",
        found_items=insecure_forms,
    )


def run_all_checks(ctx: ScanContext) -> list[CheckResult]:
    return [
        check_https(ctx),
        check_privacy_policy(ctx),
        check_imprint(ctx),
        check_cookie_banner(ctx),
        check_trackers(ctx),
        check_security_headers(ctx),
        check_hsts(ctx),
        check_forms_https(ctx),
    ]
