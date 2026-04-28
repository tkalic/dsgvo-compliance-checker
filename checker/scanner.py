"""
scanner.py — Core website scanner.

Fetches a URL, builds a ScanContext, and runs all compliance checks.
"""

import time
from dataclasses import dataclass, field
from typing import Optional

import requests
from bs4 import BeautifulSoup

from checker.checks import ScanContext, CheckResult, run_all_checks

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (compatible; DSGVO-Compliance-Checker/1.0; "
        "+https://github.com/tkalic/dsgvo-compliance-checker)"
    )
}
TIMEOUT = 15


@dataclass
class ScanResult:
    url: str
    final_url: str
    scanned_at: str
    duration_seconds: float
    checks: list[CheckResult]
    error: Optional[str] = None

    @property
    def passed(self) -> list[CheckResult]:
        return [c for c in self.checks if c.passed]

    @property
    def failed(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed]

    @property
    def critical_failures(self) -> list[CheckResult]:
        return [c for c in self.checks if not c.passed and c.severity == "critical"]

    @property
    def score(self) -> int:
        if not self.checks:
            return 0
        return round(len(self.passed) / len(self.checks) * 100)

    @property
    def rating(self) -> str:
        if self.score >= 90:
            return "A"
        elif self.score >= 75:
            return "B"
        elif self.score >= 60:
            return "C"
        elif self.score >= 40:
            return "D"
        return "F"


def scan(url: str) -> ScanResult:
    """
    Scan a website for DSGVO/GDPR compliance issues.

    Args:
        url: Website URL to scan (http:// or https://)

    Returns:
        ScanResult with all check results.
    """
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    start = time.perf_counter()
    scanned_at = time.strftime("%Y-%m-%dT%H:%M:%S")

    try:
        response = requests.get(url, headers=HEADERS, timeout=TIMEOUT,
                                allow_redirects=True)
        response.raise_for_status()
    except requests.exceptions.SSLError:
        # Try HTTP fallback to still run non-HTTPS checks
        try:
            http_url = url.replace("https://", "http://")
            response = requests.get(http_url, headers=HEADERS, timeout=TIMEOUT,
                                    allow_redirects=True)
        except Exception as e:
            return ScanResult(
                url=url, final_url=url, scanned_at=scanned_at,
                duration_seconds=round(time.perf_counter() - start, 2),
                checks=[], error=f"Connection failed: {e}"
            )
    except Exception as e:
        return ScanResult(
            url=url, final_url=url, scanned_at=scanned_at,
            duration_seconds=round(time.perf_counter() - start, 2),
            checks=[], error=f"Request failed: {e}"
        )

    soup = BeautifulSoup(response.text, "html.parser")
    ctx = ScanContext(
        url=url,
        html=response.text,
        headers=dict(response.headers),
        soup=soup,
        response_url=response.url,
    )

    checks = run_all_checks(ctx)
    duration = round(time.perf_counter() - start, 2)

    return ScanResult(
        url=url,
        final_url=response.url,
        scanned_at=scanned_at,
        duration_seconds=duration,
        checks=checks,
    )
