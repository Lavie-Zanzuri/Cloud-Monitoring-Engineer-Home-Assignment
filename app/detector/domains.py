"""Domain helpers shared by the sender check and the link check.

Kept dependency-free on purpose: a short list of two-part suffixes covers the
cases we care about; `tldextract` would be the next step for full accuracy.
"""
from __future__ import annotations

import re

# Suffixes made of two labels, so the registered domain needs three labels.
_TWO_PART_SUFFIXES = {
    "co.il", "org.il", "ac.il", "gov.il", "net.il", "muni.il",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "co.jp", "co.nz", "co.za", "com.br", "com.cn", "com.tr",
}

# Brand -> its real registered domains. Used to spot impersonation.
BRANDS: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "live.com", "outlook.com", "office365.com"},
    "office365": {"microsoft.com", "office.com", "office365.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"apple.com", "icloud.com"},
    "google": {"google.com", "youtube.com", "googlemail.com", "google-analytics.com",
               "googleusercontent.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.de", "amazon.in", "amazon.co.il",
               "amazon.fr", "amazon.it", "amazon.es", "amazon.ca", "amazonses.com"},
    "netflix": {"netflix.com"},
    "facebook": {"facebook.com", "facebookmail.com", "meta.com"},
    "instagram": {"instagram.com", "facebookmail.com", "meta.com"},
    "linkedin": {"linkedin.com"},
    "github": {"github.com"},
    "dropbox": {"dropbox.com"},
    "docusign": {"docusign.com", "docusign.net"},
    "dhl": {"dhl.com", "dhl.co.il"},
    "fedex": {"fedex.com"},
    "wellsfargo": {"wellsfargo.com"},
    "chase": {"chase.com"},
    "leumi": {"leumi.co.il"},
    "hapoalim": {"bankhapoalim.co.il"},
}

# Mailboxes anyone can register - a "company" writing from one is a red flag.
FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "live.com",
    "aol.com", "icloud.com", "mail.ru", "yandex.ru", "proton.me", "protonmail.com",
    "gmx.com", "walla.co.il",
}

# Characters attackers swap for look-alikes. Multi-char swaps first.
_HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"),
               ("5", "s"), ("@", "a"), ("$", "s")]


def domain_of(address: str) -> str:
    """'Bob <bob@Mail.Example.com>' or 'bob@mail.example.com' -> 'mail.example.com'."""
    return address.rsplit("@", 1)[-1].strip(" <>.").lower() if "@" in address else ""


def registered_domain(host: str) -> str:
    """'bounce.linkedin.com' -> 'linkedin.com';  'mail.bank.co.il' -> 'bank.co.il'."""
    labels = [label for label in host.lower().strip(".").split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    keep = 3 if ".".join(labels[-2:]) in _TWO_PART_SUFFIXES else 2
    return ".".join(labels[-keep:])


def domain_label(host: str) -> str:
    """The name part without the suffix: 'paypa1-security.com' -> 'paypa1-security'."""
    return registered_domain(host).split(".")[0]


def normalize_homoglyphs(text: str) -> str:
    text = text.lower()
    for fake, real in _HOMOGLYPHS:
        text = text.replace(fake, real)
    return text


def levenshtein(a: str, b: str) -> int:
    """Minimum single-character edits (insert/delete/replace) turning a into b."""
    if len(a) < len(b):
        a, b = b, a
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1,              # delete
                               current[j - 1] + 1,           # insert
                               previous[j - 1] + (ca != cb)))  # replace
        previous = current
    return previous[-1]


def is_official_domain(host: str, brand: str) -> bool:
    return registered_domain(host) in BRANDS.get(brand, set())


def brand_lookalike(host: str) -> tuple[str, str] | None:
    """If `host` imitates a known brand, return (brand, reason). Otherwise None.

    Catches: 'paypa1.com' (homoglyph), 'gooogle.com' (typo),
    'paypal-security.com' / 'paypal.com.evil.ru' (brand inside a foreign domain).
    """
    if not host:
        return None
    reg = registered_domain(host)
    label = domain_label(host)
    normalized_host = normalize_homoglyphs(host)
    normalized_label = normalize_homoglyphs(label)

    for brand, official in BRANDS.items():
        if reg in official:
            return None  # it IS the real brand
    for brand in BRANDS:
        if label == brand:
            return brand, f"'{reg}' uses the {brand} name on a non-official domain"
        if normalized_label == brand:
            return brand, f"'{reg}' imitates {brand} using look-alike characters"
        # Edit distance only for longer names: short ones collide with real words
        # ("ample" is one letter away from "apple").
        if len(brand) >= 6:
            max_distance = 2 if len(brand) >= 9 else 1
            if 0 < levenshtein(normalized_label, brand) <= max_distance:
                return brand, f"'{reg}' is one typo away from {brand}"
        # Brand appears as a whole word somewhere in a foreign domain.
        if len(brand) >= 4 and re.search(rf"(^|[.\-]){re.escape(brand)}([.\-]|$)",
                                         normalized_host):
            how = "" if normalized_host == host.lower() else " (written with look-alike characters)"
            return brand, (f"'{host}' contains '{brand}'{how} "
                           f"but is not an official {brand} domain")
    return None


def is_punycode(host: str) -> bool:
    """Internationalised domains are encoded as 'xn--...'. Used for homograph attacks."""
    return any(label.startswith("xn--") for label in host.lower().split("."))
