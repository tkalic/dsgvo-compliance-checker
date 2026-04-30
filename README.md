# DSGVO Compliance Checker

A Python-based tool that scans websites for DSGVO/GDPR compliance issues — checks for cookie banners, privacy policies, third-party trackers, security headers, and more. Comes with a CLI and a web UI. Generates detailed HTML audit reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-62%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What It Checks (14 checks)

| Check | Severity | Reference |
|-------|----------|-----------|
| HTTPS encryption | Critical | Art. 32 DSGVO |
| Privacy policy present | Critical | Art. 13/14 DSGVO |
| Imprint / Impressum | Warning | §5 TMG |
| Cookie consent banner | Critical | Art. 6 DSGVO + §25 TTDSG |
| Third-party trackers | Critical | Art. 6 DSGVO |
| Google Fonts (external) | Critical | Art. 6 DSGVO · LG München 20.01.2022 |
| YouTube embeds | Critical | Art. 6 DSGVO |
| Mixed content | Warning | Art. 32 DSGVO |
| Cookie security attributes | Warning | Art. 32 DSGVO |
| CAPTCHA provider | Warning | Art. 6 DSGVO |
| DNS prefetch / preconnect | Info | Art. 6 DSGVO |
| Security headers | Warning | Art. 32 DSGVO |
| HSTS enforcement | Warning | Art. 32 DSGVO |
| Secure form submission | Critical | Art. 32 DSGVO |

---

## Quick Start

```bash
git clone https://github.com/tkalic/dsgvo-compliance-checker
cd dsgvo-compliance-checker
pip install -r requirements.txt

# CLI — scan a website
python3 main.py scan https://example.com

# CLI — scan with HTML report
python3 main.py scan https://example.com --report audit.html

# Web UI — browser interface with scan, compare, and history
python3 web/app.py
# → http://localhost:5000
```

---

## Web UI

The web interface runs locally and provides three views:

**Scan** — enter any URL and get a full compliance report in the browser, including score, rating, and per-check results with DSGVO article references.

**Compare** — enter two URLs side by side to compare their compliance posture directly.

**History** — the last 20 scans are stored in memory. Click any entry to re-run it.

---

## CLI Example Output

```
  Scanning: https://www.bsi.bund.de

  ──────────────────────────────────────────────────
  Final URL      : https://www.bsi.bund.de/DE/Home/home_node.html
  Scan duration  : 2.1s
  Checks run     : 14
  Score          : 93/100
  Rating         : A
  ──────────────────────────────────────────────────

  ✓  HTTPS Encryption               Site is served over HTTPS.
  ✓  Privacy Policy                 Privacy policy link found
  ✓  Imprint (Impressum)            Imprint link found
  ✓  Cookie Consent Banner          Cookie framework detected
  ✓  Third-Party Trackers           No third-party trackers detected.
  ✓  Google Fonts (External)        No external Google Fonts detected.
  ✓  YouTube Embeds                 No standard YouTube embeds detected.
  ✓  Mixed Content                  No mixed content detected.
  ✓  Cookie Security Attributes     No Set-Cookie headers on this page.
  ✓  CAPTCHA Provider               No Google reCAPTCHA detected.
  ✓  DNS Prefetch / Preconnect      No third-party prefetch directives.
  ✗  Security Headers               4/5 headers present. Missing: permissions-policy
     → Add missing headers: permissions-policy
  ✓  HSTS                           HSTS header present: max-age=31536000
  ✓  Secure Form Submission         All forms submit over HTTPS.
```

---

## HTML Audit Report

Pass `--report <filename>.html` to generate a compliance-annotated audit report:

```bash
python3 main.py scan https://example.com --report audit.html
```

The report includes a compliance score (A–F), per-check results with DSGVO article references, and concrete remediation recommendations.

---

## Project Structure

```
dsgvo-compliance-checker/
├── checker/
│   ├── __init__.py
│   ├── scanner.py         # Core scan logic
│   ├── checks.py          # 14 individual compliance checks
│   ├── report.py          # HTML report generator
│   └── trackers.txt       # Known third-party tracker domains
├── tests/
│   └── test_checker.py    # 62 unit tests (pytest)
├── web/
│   ├── app.py             # Flask web UI
│   └── templates/
│       └── index.html     # Scan, compare, and history views
├── main.py                # CLI entry point
├── requirements.txt
└── README.md
```

---

## Compliance Context

This tool checks the technical indicators that DSGVO compliance auditors look for:

- **Art. 6 DSGVO** — Lawful basis: third-party trackers, Google Fonts, YouTube embeds, and reCAPTCHA loaded without consent are direct violations
- **Art. 13/14 DSGVO** — Information obligations: a privacy policy is legally required
- **Art. 32 DSGVO** — Security of processing: HTTPS, HSTS, security headers, cookie attributes, and secure form submission
- **§25 TTDSG** — German ePrivacy: cookie consent must be obtained before setting non-essential cookies
- **§5 TMG** — German Telemedia Act: commercial websites must display an imprint
- **LG München 20.01.2022 (Az. 3 O 17493/20)** — Loading Google Fonts from Google servers is illegal without consent

> This tool checks technical indicators only and does not constitute legal advice. Full DSGVO compliance requires ongoing organizational measures beyond what can be detected automatically.

---

## Tests

```bash
python3 -m pytest tests/ -v
```

62 tests covering all 14 checks, scoring logic, and report generation.

---

## Author

Edwin Tkalic — [github.com/tkalic](https://github.com/tkalic) · [linkedin.com/in/edwin-tkalic-2b4b51287](https://linkedin.com/in/edwin-tkalic-2b4b51287)