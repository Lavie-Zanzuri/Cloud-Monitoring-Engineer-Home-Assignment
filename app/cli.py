"""Temporary CLI: prints what the parser extracted. Will become the full detector CLI."""
import sys
from pprint import pprint

from detector.parser import parse_email

if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python cli.py <email-file>")
    with open(sys.argv[1], encoding="utf-8", errors="replace") as f:
        pprint(parse_email(f.read()), width=100)
