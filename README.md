# DSGVO Compliance Checker

A Python-based command-line tool that scans websites for DSGVO/GDPR compliance issues — checks for cookie banners, privacy policies, third-party trackers, security headers, and more. Generates detailed HTML audit reports.

![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)
![Tests](https://img.shields.io/badge/Tests-35%20passed-brightgreen)
![License](https://img.shields.io/badge/License-MIT-green)

---

## What It Checks

| Check | Severity | DSGVO Reference |
|-------|----------|-----------------|
| HTTPS encryption | Critical | Art. 32 DSGVO |
| Privacy policy present | Critical | Art. 13/14 DSGVO |
| Imprint / Impressum | Warning | §5 TMG |
| Cookie consent banner | Critical | Art. 6 DSGVO + §25 TTDSG |
| Third-party trackers | Critical | Art. 6 DSGVO |
| Security headers | Warning | Art. 32 DSGVO |
| HSTS enforcement | Warning | Art. 32 DSGVO |
| Secure form submission | Critical | Art. 32 DSGVO |

---

## Quick Start

```bash
git clone https://github.com/tkalic/dsgvo-compliance-checker
cd dsgvo-compliance-checker
pip install -r requirements.txt

# Scan a website
python3 main.py scan https://example.com

# Scan and save HTML report
python3 main.py scan https://example.com --report audit.html
```

---

## Example Output

```
  Scanning: https://www.bsi.bund.de

  ──────────────────────────────────────────────────
  Final URL      : https://www.bsi.bund.de/DE/Home/home_node.html
  Scan duration  : 2.12s
  Checks run     : 8
  Score          : 88/100
  Rating         : B
  ──────────────────────────────────────────────────

  ✓  HTTPS Encryption               Site is served over HTTPS.
  ✓  Privacy Policy                 Privacy policy link found
  ✓  Imprint (Impressum)            Imprint link found
  ✓  Cookie Consent Banner          Cookie framework detected: cookiebanner
  ✓  Third-Party Trackers           No third-party trackers detected.
  ✗  Security Headers               4/5 headers present. Missing: permissions-policy
     → Add missing headers: permissions-policy
  ✓  HSTS                           HSTS header present: max-age=31536000
  ✓  Secure Form Submission         All forms submit over HTTPS.

  Report saved: audit.html
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
│   ├── scanner.py        # Core scan logic
│   ├── checks.py         # Individual compliance checks
│   ├── report.py         # HTML report generator
│   └── trackers.txt      # Known third-party tracker domains
├── tests/
│   └── test_checker.py   # 35 unit tests (pytest)
├── main.py               # CLI entry point
├── requirements.txt
└── README.md
```

---

## Compliance Context

This tool checks the technical indicators that DSGVO compliance auditors look for:

- **Art. 6 DSGVO** — Lawful basis for processing: third-party trackers without consent violate this directly
- **Art. 13/14 DSGVO** — Information obligations: a privacy policy is legally required
- **Art. 32 DSGVO** — Security of processing: HTTPS, HSTS, and security headers are technical measures required by this article
- **§25 TTDSG** — German implementation of the ePrivacy Directive: cookie consent must be obtained before setting non-essential cookies
- **§5 TMG** — German Telemedia Act: commercial websites must display an imprint

> This tool checks technical indicators only and does not constitute legal advice. Full DSGVO compliance requires ongoing organizational measures beyond what can be detected automatically.

---

## Tests

```bash
python3 -m pytest tests/ -v
```

35 tests covering all checks, scoring logic, and report generation.

---

## Author

Edwin Tkalic — [github.com/tkalic](https://github.com/tkalic) · [linkedin.com/in/edwin-tkalic-2b4b51287](https://linkedin.com/in/edwin-tkalic-2b4b51287)
