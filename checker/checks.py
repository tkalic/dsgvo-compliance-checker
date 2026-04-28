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


def check_google_fonts(ctx: ScanContext) -> CheckResult:
    """
    Check for externally loaded Google Fonts.

    LG München, 20.01.2022 (Az. 3 O 17493/20): Loading Google Fonts from
    Google servers transmits the visitor's IP address to Google without consent,
    violating Art. 6 DSGVO. Self-hosting fonts is the compliant alternative.
    """
    patterns = ["fonts.googleapis.com", "fonts.gstatic.com"]
    found = []

    # Check <link> tags
    for tag in ctx.soup.find_all("link", href=True):
        href = tag.get("href", "")
        if any(p in href for p in patterns):
            found.append(href[:80])

    # Check inline styles and scripts
    for pattern in patterns:
        if pattern in ctx.html and pattern not in str(found):
            found.append(pattern)

    found = list(set(found))
    passed = len(found) == 0

    return CheckResult(
        name="Google Fonts (External)",
        passed=passed,
        severity="critical",
        detail="No external Google Fonts detected." if passed else f"External Google Fonts detected: {', '.join(found[:2])}",
        recommendation="" if passed else "Self-host your fonts instead. Google Fonts can be downloaded and served from your own server.",
        gdpr_reference="Art. 6 DSGVO — LG München 20.01.2022 (Az. 3 O 17493/20)",
        found_items=found,
    )


def check_youtube_embeds(ctx: ScanContext) -> CheckResult:
    """
    Check for YouTube iframes without privacy-enhanced mode.

    Embedding youtube.com/embed (non-nocookie) loads tracking scripts
    from Google/YouTube without user consent — same legal basis as Google Fonts.
    Use youtube-nocookie.com as the privacy-compliant alternative.
    """
    iframes = ctx.soup.find_all("iframe", src=True)
    regular = []
    nocookie = []

    for iframe in iframes:
        src = iframe.get("src", "")
        if "youtube.com/embed" in src and "youtube-nocookie.com" not in src:
            regular.append(src[:80])
        elif "youtube-nocookie.com" in src:
            nocookie.append(src[:80])

    passed = len(regular) == 0
    detail = "No standard YouTube embeds detected."
    if regular:
        detail = f"{len(regular)} YouTube embed(s) using tracking mode found."
    elif nocookie:
        detail = f"YouTube embeds use privacy-enhanced mode (youtube-nocookie.com). ✓"

    return CheckResult(
        name="YouTube Embeds",
        passed=passed,
        severity="critical",
        detail=detail,
        recommendation="" if passed else "Replace youtube.com/embed URLs with youtube-nocookie.com/embed to prevent tracking without consent.",
        gdpr_reference="Art. 6 DSGVO — IP transmission to Google without consent",
        found_items=regular,
    )


def check_mixed_content(ctx: ScanContext) -> CheckResult:
    """
    Check for mixed content — HTTP resources loaded on an HTTPS page.

    Mixed content weakens the security of HTTPS pages and may expose
    user data. Browsers block or warn about mixed content per Art. 32 DSGVO.
    """
    if not ctx.response_url.startswith("https://"):
        return CheckResult(
            name="Mixed Content",
            passed=False,
            severity="info",
            detail="Site does not use HTTPS — mixed content check skipped.",
            recommendation="Enable HTTPS first.",
            gdpr_reference="Art. 32 DSGVO",
        )

    http_resources = []

    # Check src attributes on scripts, images, iframes
    for tag in ctx.soup.find_all(["script", "img", "iframe", "source", "audio", "video"], src=True):
        src = tag.get("src", "")
        if src.startswith("http://"):
            http_resources.append(f"<{tag.name}> {src[:60]}")

    # Check href on link tags (stylesheets)
    for tag in ctx.soup.find_all("link", href=True):
        href = tag.get("href", "")
        if href.startswith("http://"):
            http_resources.append(f"<link> {href[:60]}")

    passed = len(http_resources) == 0
    return CheckResult(
        name="Mixed Content",
        passed=passed,
        severity="warning",
        detail="No mixed content detected." if passed else f"{len(http_resources)} HTTP resource(s) loaded on HTTPS page.",
        recommendation="" if passed else "Replace all HTTP resource URLs with HTTPS equivalents.",
        gdpr_reference="Art. 32 DSGVO — Integrity and confidentiality",
        found_items=http_resources[:5],
    )


def run_all_checks(ctx: ScanContext) -> list[CheckResult]:
    return [
        check_https(ctx),
        check_privacy_policy(ctx),
        check_imprint(ctx),
        check_cookie_banner(ctx),
        check_trackers(ctx),
        check_google_fonts(ctx),
        check_youtube_embeds(ctx),
        check_mixed_content(ctx),
        check_security_headers(ctx),
        check_hsts(ctx),
        check_forms_https(ctx),
    ]
