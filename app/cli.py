"""Scan an email file for phishing indicators.

    python cli.py samples/phishing_paypal.eml
    python cli.py samples/phishing_paypal.eml --json

Exit code: 0 = Safe, 1 = Suspicious, 2 = Phishing (handy in scripts), 3 = error.
"""
from __future__ import annotations

import argparse
import json
import sys

from detector.analyzer import AnalysisResult, analyze

EXIT_CODES = {"Safe": 0, "Suspicious": 1, "Phishing": 2}
ICONS = {"Safe": "✅", "Suspicious": "⚠️ ", "Phishing": "🚨"}


def render(result: AnalysisResult) -> str:
    line = "=" * 64
    sender = f"{result.from_name} <{result.from_address}>" if result.from_address else "(no headers)"
    out = [
        line,
        f" {ICONS[result.verdict]} Verdict: {result.verdict.upper()}    Risk score: {result.score}/100",
        line,
        f" From:    {sender}",
        f" Subject: {result.subject or '(none)'}",
        "",
    ]
    if not result.findings:
        out.append(" No phishing indicators found.")
    else:
        out.append(f" Indicators found ({len(result.findings)}):")
        for f in result.findings:
            out.append(f"  [{f.category:<11}] +{f.points:<3} {f.title}")
            out.append(f"  {'':13}       {f.detail}")
        out.append("")
        breakdown = ", ".join(f"{c} {p}" for c, p in result.category_scores.items())
        out.append(f" Score by category (each capped at 50): {breakdown}")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Scan an email for phishing indicators.")
    parser.add_argument("file", help="email file (.eml or plain text)")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    args = parser.parse_args(argv)

    try:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            raw = f.read()
    except OSError as e:
        print(f"error: cannot read {args.file}: {e.strerror}", file=sys.stderr)
        return 3

    result = analyze(raw)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))
    else:
        print(render(result))
    return EXIT_CODES[result.verdict]


if __name__ == "__main__":
    sys.exit(main())
