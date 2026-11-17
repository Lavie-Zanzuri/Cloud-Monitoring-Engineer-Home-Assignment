"""Spoofed-sender analysis: does the From/Reply-To/Return-Path look like someone
pretending to be a trusted brand?

Only runs when the input had headers. Pasted body text has no sender, and
missing information is not evidence of phishing.
"""
from __future__ import annotations

import re

from ..domains import (BRANDS, FREE_EMAIL_DOMAINS, brand_lookalike, domain_of,
                       is_official_domain, is_punycode, registered_domain)
from ..models import Finding, ParsedEmail

POINTS_LOOKALIKE_DOMAIN = 35
POINTS_EMAIL_IN_DISPLAY_NAME = 30
POINTS_PUNYCODE = 25
POINTS_DISPLAY_NAME_BRAND = 25
POINTS_REPLY_TO_MISMATCH = 15
POINTS_RETURN_PATH_MISMATCH = 10

_EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@[\w-]+(\.[\w-]+)+")


def _finding(title: str, detail: str, points: int) -> Finding:
    return Finding(category="sender", title=title, detail=detail, points=points)


def _brand_in_display_name(name: str) -> str | None:
    words = set(re.findall(r"[a-z0-9]+", name.lower()))
    joined = re.sub(r"[^a-z0-9]", "", name.lower())      # "Wells Fargo" -> "wellsfargo"
    for brand in BRANDS:
        if brand in words or (len(brand) >= 6 and brand in joined):
            return brand
    return None


def check_sender(email: ParsedEmail) -> list[Finding]:
    if not email.has_headers or not email.from_address:
        return []

    findings: list[Finding] = []
    from_host = domain_of(email.from_address)
    from_reg = registered_domain(from_host)

    # 1. Look-alike / brand-in-foreign-domain sender
    lookalike = brand_lookalike(from_host)
    if lookalike:
        _, reason = lookalike
        findings.append(_finding("Look-alike sender domain", reason, POINTS_LOOKALIKE_DOMAIN))

    # 2. Punycode (IDN homograph) sender domain
    if is_punycode(from_host):
        findings.append(_finding(
            "Internationalised (punycode) sender domain",
            f"'{from_host}' uses punycode, often used to fake domains with foreign letters",
            POINTS_PUNYCODE))

    # 3. Display name contains a different email address
    shown = _EMAIL_IN_TEXT.search(email.from_name)
    if shown and shown.group(0).lower() != email.from_address:
        findings.append(_finding(
            "Fake address in display name",
            f"Name shows '{shown.group(0)}' but the real sender is '{email.from_address}'",
            POINTS_EMAIL_IN_DISPLAY_NAME))

    # 4. Display name claims a brand the domain doesn't belong to
    brand = _brand_in_display_name(email.from_name)
    if brand and not is_official_domain(from_host, brand) and not lookalike:
        extra = " (a free email provider)" if from_reg in FREE_EMAIL_DOMAINS else ""
        findings.append(_finding(
            "Display name impersonates a brand",
            f"Name '{email.from_name}' suggests {brand}, but it was sent from '{from_reg}'{extra}",
            POINTS_DISPLAY_NAME_BRAND))

    # 5. Replies go somewhere else
    if email.reply_to:
        reply_reg = registered_domain(domain_of(email.reply_to))
        if reply_reg and reply_reg != from_reg:
            findings.append(_finding(
                "Reply-To differs from sender",
                f"Replies go to '{email.reply_to}', not to '{from_reg}'",
                POINTS_REPLY_TO_MISMATCH))

    # 6. Bounce address from another domain (weak signal: legit mailing services do this too)
    if email.return_path:
        rp_reg = registered_domain(domain_of(email.return_path))
        if rp_reg and rp_reg != from_reg:
            findings.append(_finding(
                "Return-Path differs from sender",
                f"Sent through '{rp_reg}' while claiming to be '{from_reg}'",
                POINTS_RETURN_PATH_MISMATCH))

    return findings
