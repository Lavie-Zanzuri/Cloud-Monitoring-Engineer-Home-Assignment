import pytest

from detector.checks.links import check_links
from detector.models import Link, ParsedEmail
from detector.parser import parse_email


def _titles(*links):
    return [f.title for f in check_links(ParsedEmail(links=list(links)))]


@pytest.mark.parametrize("url, expected_title", [
    ("http://185.23.44.10/login", "Link to an IP address"),
    ("https://[2001:db8::1]/x", "Link to an IP address"),
    ("http://3105437450/", "Link to an IP address"),          # IPv4 as a single number
    ("https://paypal.com@evil.ru/login", "'@' trick in link"),
    ("https://bit.ly/3xYz", "URL shortener"),
    ("https://micros0ft-login.com", "Look-alike link domain"),
    ("https://login.example.xyz", "Suspicious top-level domain"),
    ("https://xn--pypal-4ve.com", "Punycode link domain"),
    ("javascript:alert(1)", "Dangerous link type"),
    ("data:text/html;base64,PGgxPg==", "Dangerous link type"),
])
def test_single_bad_link(url, expected_title):
    assert expected_title in _titles(Link(url, ""))


@pytest.mark.parametrize("url", [
    "https://github.com/settings/keys",
    "https://www.linkedin.com/comm/jobs/view/123",
    "https://apps.microsoft.com/store/detail/9WZDNCRFJ4Q7",
    "https://itunes.apple.com/us/app/linkedin/id288429040",
    "https://play.google.com/store/apps/details?id=com.linkedin.android",
    "mailto:someone@example.com",
    "tel:+972501234567",
    "#top",
    "/relative/path",
])
def test_clean_links(url):
    assert _titles(Link(url, "")) == []


def test_display_text_mismatch():
    assert "Link text hides the real destination" in _titles(
        Link("https://evil.ru/login", "https://www.paypal.com/login"))


def test_display_text_same_registered_domain_is_fine():
    assert _titles(Link("https://www.paypal.com/signin", "paypal.com")) == []


def test_normal_words_in_display_text_are_not_urls():
    assert _titles(Link("https://github.com/x", "Click here to verify now")) == []


def test_same_problem_counted_once_per_domain():
    links = [Link(f"https://bit.ly/{i}", "") for i in range(10)]
    assert _titles(*links) == ["URL shortener"]


def test_http_counted_once_per_email():
    links = [Link("http://a.example.com", ""), Link("http://b.example.org", "")]
    assert _titles(*links) == ["Unencrypted link (http)"]


def test_phishing_sample():
    email = parse_email(open("samples/phishing_paypal.eml").read())
    assert sorted(_t.title for _t in check_links(email)) == sorted([
        "Link to an IP address",
        "Link text hides the real destination",
        "Unencrypted link (http)",
        "URL shortener",
    ])


def test_plain_text_sample():
    email = parse_email(open("samples/plain_text_phish.txt").read())
    titles = {f.title for f in check_links(email)}
    assert {"Look-alike link domain", "Suspicious top-level domain"} <= titles


def test_legit_samples():
    for path in ("samples/legit_github.eml",):
        assert check_links(parse_email(open(path).read())) == []
