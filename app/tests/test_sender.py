import pytest

from detector.checks.sender import check_sender
from detector.domains import brand_lookalike, levenshtein, registered_domain
from detector.models import ParsedEmail
from detector.parser import parse_email


def _sender(from_addr, name="", reply_to="", return_path=""):
    return ParsedEmail(from_name=name, from_address=from_addr, reply_to=reply_to,
                       return_path=return_path, has_headers=True)


def _titles(email):
    return [f.title for f in check_sender(email)]


# ---------- domain helpers ----------

@pytest.mark.parametrize("host, expected", [
    ("linkedin.com", "linkedin.com"),
    ("bounce.linkedin.com", "linkedin.com"),
    ("mail.bank.co.il", "bank.co.il"),
    ("a.b.c.example.co.uk", "example.co.uk"),
    ("localhost", "localhost"),
])
def test_registered_domain(host, expected):
    assert registered_domain(host) == expected


def test_levenshtein():
    assert levenshtein("paypal", "paypal") == 0
    assert levenshtein("paypa", "paypal") == 1
    assert levenshtein("gooogle", "google") == 1


@pytest.mark.parametrize("host", [
    "paypa1.com",              # 1 -> l
    "micros0ft.com",           # 0 -> o
    "arnazon.com",             # rn -> m
    "gooogle.com",             # typo
    "linkedln.com",            # "ln" instead of "in"
    "app1e.com",               # homoglyph on a short brand
    "paypal.net",              # real name, wrong domain
    "paypal-security.com",     # brand + extra word
    "paypa1-security.com",     # homoglyph + extra word
    "paypal.com.evil.ru",      # brand as a subdomain of a foreign domain
    "secure.linkedin-jobs.net",
])
def test_lookalike_domains_detected(host):
    assert brand_lookalike(host) is not None


@pytest.mark.parametrize("host", [
    "paypal.com", "www.paypal.com", "bounce.linkedin.com", "github.com",
    "mail.bankhapoalim.co.il", "example.com", "gmail.com", "shop.co.il",
    # regressions: false positives found while probing real domains
    "ample.com",               # one letter from "apple", but a real word
    "purchase.com",            # contains "chase", but not as a separate word
    "google-analytics.com",    # official Google domain
    "amazon.co.il",            # official Amazon country domain
])
def test_legit_domains_not_flagged(host):
    assert brand_lookalike(host) is None


# ---------- the check itself ----------

def test_no_headers_means_no_findings():
    assert check_sender(ParsedEmail(body_text="hi")) == []


def test_phishing_sample():
    email = parse_email(open("samples/phishing_paypal.eml").read())
    assert _titles(email) == [
        "Look-alike sender domain",
        "Reply-To differs from sender",
        "Return-Path differs from sender",
    ]


def test_legit_github_sample():
    assert check_sender(parse_email(open("samples/legit_github.eml").read())) == []


def test_legit_linkedin_with_bounce_subdomain():
    # Real-world shape: bounce address is a subdomain of the sender's domain.
    email = _sender("jobs-noreply@linkedin.com", "LinkedIn",
                    return_path="s-123@bounce.linkedin.com")
    assert check_sender(email) == []


def test_brand_name_from_free_mail():
    titles = _titles(_sender("paypal.help.desk@gmail.com", "PayPal Support"))
    assert titles == ["Display name impersonates a brand"]


def test_email_address_hidden_in_display_name():
    titles = _titles(_sender("x@evil.ru", "support@paypal.com"))
    assert "Fake address in display name" in titles


def test_punycode_sender():
    assert "Internationalised (punycode) sender domain" in _titles(
        _sender("info@xn--pypal-4ve.com"))


def test_reply_to_same_registered_domain_is_fine():
    assert check_sender(_sender("news@github.com", reply_to="support@help.github.com")) == []


def test_display_name_brand_with_space():
    titles = _titles(_sender("alerts@secure-bank-mail.com", "Wells Fargo Online"))
    assert titles == ["Display name impersonates a brand"]
