#!/usr/bin/env python3
"""
dsgvo-compliance-checker — DSGVO/GDPR compliance scanner for websites.
Author: Edwin Tkalic (github.com/tkalic)

Usage:
  python3 main.py scan <url> [--report report.html]
  python3 main.py scan https://example.com --report audit.html
"""

import argparse
import sys
from pathlib import Path

from checker.scanner import scan
from checker.report import generate_html_report

R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
C  = "\033[96m"
W  = "\033[97m"
D  = "\033[2m"
X  = "\033[0m"
BO = "\033[1m"

BANNER = f"""
{B}  ██████╗ ███████╗ ██████╗ ██╗   ██╗ ██████╗{X}
{B}  ██╔══██╗██╔════╝██╔════╝ ██║   ██║██╔═══██╗{X}   {W}{BO}DSGVO Compliance Checker v1.0{X}
{B}  ██║  ██║███████╗██║  ███╗██║   ██║██║   ██║{X}   {D}by Edwin Tkalic{X}
{B}  ██║  ██║╚════██║██║   ██║╚██╗ ██╔╝██║   ██║{X}   {D}github.com/tkalic{X}
{B}  ██████╔╝███████║╚██████╔╝ ╚████╔╝ ╚██████╔╝{X}
{B}  ╚═════╝ ╚══════╝ ╚═════╝   ╚═══╝   ╚═════╝{X}
"""

SEVERITY_COLOR = {"critical": R, "warning": Y, "info": B}
RATING_COLOR   = {"A": G, "B": G, "C": Y, "D": Y, "F": R}


def cmd_scan(args):
    url = args.url
    print(f"\n  {D}Scanning:{X} {C}{url}{X}\n")

    result = scan(url)

    if result.error:
        print(f"  {R}Error: {result.error}{X}\n")
        sys.exit(1)

    rating_col = RATING_COLOR.get(result.rating, W)
    print(f"  {D}{'─' * 50}{X}")
    print(f"  Final URL      : {result.final_url}")
    print(f"  Scan duration  : {result.duration_seconds}s")
    print(f"  Checks run     : {len(result.checks)}")
    print(f"  Score          : {result.score}/100")
    print(f"  Rating         : {rating_col}{BO}{result.rating}{X}")
    print(f"  {D}{'─' * 50}{X}\n")

    for check in result.checks:
        col = G if check.passed else SEVERITY_COLOR.get(check.severity, R)
        icon = "✓" if check.passed else "✗"
        print(f"  {col}{icon}{X}  {W}{check.name:<35}{X}  {D}{check.detail[:60]}{X}")
        if not check.passed and check.recommendation:
            print(f"     {Y}→ {check.recommendation[:80]}{X}")

    print()

    if result.critical_failures:
        print(f"  {R}Critical issues ({len(result.critical_failures)}):{X}")
        for c in result.critical_failures:
            print(f"  {R}•{X} {c.name}: {c.gdpr_reference}")
        print()

    if args.report:
        out = Path(args.report)
        generate_html_report(result, out)
        print(f"  {G}Report saved:{X} {out}\n")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="DSGVO/GDPR compliance scanner for websites",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="Scan a website")
    p_scan.add_argument("url", help="URL to scan (e.g. https://example.com)")
    p_scan.add_argument("--report", metavar="FILE", help="Save HTML report to FILE")

    return parser


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    if args.command == "scan":
        cmd_scan(args)


if __name__ == "__main__":
    main()
