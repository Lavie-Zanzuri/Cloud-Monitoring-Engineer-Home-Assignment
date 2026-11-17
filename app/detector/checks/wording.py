"""Suspicious-wording analysis.

Phrases are grouped by the psychological trick they use (urgency, threats,
asking for credentials...). Each category counts ONCE, however many phrases
match - so repeated text (e.g. the same body in text/plain and text/html)
or an email shouting "urgent" ten times can't inflate the score.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Finding, ParsedEmail


@dataclass(frozen=True)
class _Category:
    title: str
    points: int
    patterns: tuple[str, ...]


CATEGORIES = (
    _Category("Requests credentials or personal details", 20, (
        r"verify your (identity|account|password|information|details|email)",
        r"confirm your (password|credentials|account|identity|details|information)",
        r"update your (payment|billing|account|bank) (details|information|method)",
        r"(enter|provide|re-?enter) your (password|credentials|pin|card number|ssn)",
        r"keep your (current )?password",
        r"login credentials",
        r"social security number",
        r"אמת את (פרטיך|החשבון|זהותך)", r"הזן את (הסיסמה|פרטי)",
    )),
    _Category("Threatening language", 15, (
        r"account (will be|has been|is) (suspended|locked|closed|deleted|disabled|terminated|restricted)",
        r"permanently (deleted|closed|suspended|locked)",
        r"(unusual|suspicious|unauthorized) (activity|access|sign-?in|login)",
        r"legal action",
        r"security alert",
        r"החשבון שלך (יושעה|ייחסם|ייסגר|נחסם)",
    )),
    _Category("Urgency pressure", 10, (
        r"\burgent\b", r"\bimmediately\b", r"\bact now\b", r"as soon as possible",
        r"within \d+ (hours?|minutes?|days?)", r"expires? today", r"final (notice|warning)",
        r"last chance", r"limited time",
        r"דחוף", r"מיידי", r"תוך \d+ (שעות|ימים|דקות)",
    )),
    _Category("Money or prize lure", 10, (
        r"you('ve| have) won", r"\bcongratulations\b", r"gift ?card", r"wire transfer",
        r"\bbitcoin\b", r"claim your (prize|reward|refund|money)", r"lottery",
        r"זכית",
    )),
    _Category("Generic greeting", 5, (
        r"dear (customer|user|client|member|account holder|valued customer|sir|madam)",
        r"לקוח יקר",
    )),
    _Category("Pushes to click", 5, (
        r"click here", r"click (the|this) (link|button)", r"click below",
        r"לחץ כאן",
    )),
)

_COMPILED = [(c, [re.compile(p, re.IGNORECASE) for p in c.patterns]) for c in CATEGORIES]


def check_wording(email: ParsedEmail) -> list[Finding]:
    text = f"{email.subject}\n{email.body_text}"
    text = " ".join(text.split())          # collapse newlines so phrases split by a line break match
    findings: list[Finding] = []
    for category, regexes in _COMPILED:
        matches: list[str] = []
        for regex in regexes:
            m = regex.search(text)
            if m and m.group(0).lower() not in (x.lower() for x in matches):
                matches.append(m.group(0))
        if matches:
            shown = ", ".join(f"'{m}'" for m in matches[:3])
            findings.append(Finding("wording", category.title, f"Found {shown}", category.points))
    return findings
