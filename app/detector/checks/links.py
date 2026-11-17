"""Suspicious-link analysis.

URLs are parsed with urllib (not regex) so tricks like 'http://paypal.com@evil.ru'
resolve to the host the browser would really visit.
"""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from ..domains import brand_lookalike, is_punycode, registered_domain
from ..models import Finding, Link, ParsedEmail

POINTS_DISPLAY_MISMATCH = 35
POINTS_IP_ADDRESS = 30
POINTS_LOOKALIKE = 30
POINTS_DANGEROUS_SCHEME = 30
POINTS_AT_SIGN = 25
POINTS_PUNYCODE = 20
POINTS_SHORTENER = 15
POINTS_SUSPICIOUS_TLD = 15
POINTS_NO_HTTPS = 5

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "t.ly", "s.id",
}
# TLDs that are cheap/free and over-represented in phishing reports.
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "zip", "mov", "click", "country",
    "work", "rest", "buzz", "icu", "cam", "support", "live", "loan", "monster",
}
SAFE_SCHEMES = {"http", "https"}
IGNORED_SCHEMES = {"mailto", "tel", "cid", "sms"}       # not web links
DANGEROUS_SCHEMES = {"javascript", "data", "file", "vbscript"}

# Display text that itself looks like a URL or a bare domain ("paypal.com/login").
_LOOKS_LIKE_URL = re.compile(r"^(https?://)?([\w-]+\.)+[a-z]{2,}(:\d+)?(/\S*)?$", re.IGNORECASE)


def _split(url: str):
    url = url.strip()
    if url.lower().startswith("www."):
        url = "http://" + url
    try:
        return urlsplit(url)
    except ValueError:          # e.g. malformed IPv6 brackets
        return None


def _is_ip(host: str) -> bool:
    if host.isdigit():          # "http://3105437450/" - an IPv4 written as one number
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _display_host(text: str) -> str:
    text = text.strip()
    if not _LOOKS_LIKE_URL.match(text):
        return ""
    parts = _split(text if "://" in text else "http://" + text)
    return (parts.hostname or "") if parts else ""


def _findings_for_link(link: Link) -> list[tuple[str, str, int, str]]:
    """Returns (title, detail, points, dedupe_key) tuples for one link."""
    parts = _split(link.url)
    if parts is None:
        return []
    scheme = parts.scheme.lower()
    if scheme in IGNORED_SCHEMES or (not scheme and not parts.netloc):
        return []           # mailto:, tel:, relative links, anchors
    if scheme in DANGEROUS_SCHEMES:
        return [("Dangerous link type", f"Link uses '{scheme}:' which can run code or hide content",
                 POINTS_DANGEROUS_SCHEME, scheme)]
    if scheme not in SAFE_SCHEMES:
        return []

    host = (parts.hostname or "").lower()
    if not host:
        return []
    reg = registered_domain(host)
    out: list[tuple[str, str, int, str]] = []

    if "@" in parts.netloc:
        out.append(("'@' trick in link",
                    f"'{link.url[:80]}' really goes to '{host}' - the part before '@' is ignored",
                    POINTS_AT_SIGN, host))

    if _is_ip(host):
        out.append(("Link to an IP address",
                    f"'{link.url[:80]}' points to a raw IP instead of a domain",
                    POINTS_IP_ADDRESS, host))
    else:
        lookalike = brand_lookalike(host)
        if lookalike:
            out.append(("Look-alike link domain", lookalike[1], POINTS_LOOKALIKE, reg))
        if is_punycode(host):
            out.append(("Punycode link domain", f"'{host}' uses punycode", POINTS_PUNYCODE, reg))
        if reg in URL_SHORTENERS:
            out.append(("URL shortener", f"'{reg}' hides the real destination",
                        POINTS_SHORTENER, reg))
        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            out.append(("Suspicious top-level domain",
                        f"'.{tld}' is cheap and common in phishing ({host})",
                        POINTS_SUSPICIOUS_TLD, reg))

    shown_host = _display_host(link.display_text)
    if shown_host and registered_domain(shown_host) != reg:
        out.append(("Link text hides the real destination",
                    f"Shows '{link.display_text[:60]}' but goes to '{host}'",
                    POINTS_DISPLAY_MISMATCH, f"{shown_host}->{host}"))

    if scheme == "http":
        out.append(("Unencrypted link (http)", f"'{host}' is not using https",
                    POINTS_NO_HTTPS, "http"))   # one key -> counted once per email
    return out


def check_links(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for link in email.links:
        for title, detail, points, key in _findings_for_link(link):
            if (title, key) in seen:
                continue                     # same problem, same domain: count once
            seen.add((title, key))
            findings.append(Finding("links", title, detail, points))
    return findings
