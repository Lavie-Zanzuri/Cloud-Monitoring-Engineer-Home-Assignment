import pytest

from detector.checks.wording import check_wording
from detector.models import ParsedEmail
from detector.parser import parse_email


def _wording(text, subject=""):
    return {f.title: f.points for f in check_wording(ParsedEmail(subject=subject, body_text=text))}



@pytest.mark.parametrize("text, title", [
    ("Please verify your account today", "Requests credentials or personal details"),
    ("Your account will be suspended", "Threatening language"),
    ("We noticed unusual activity", "Threatening language"),
    ("Reply within 24 hours", "Urgency pressure"),
    ("You have won a gift card!", "Money or prize lure"),
    ("Dear Customer,", "Generic greeting"),
    ("Click here to continue", "Pushes to click"),
    ("החשבון שלך יושעה", "Threatening language"),
    ("דחוף: אמת את פרטיך", "Requests credentials or personal details"),
])
def test_phrases_detected(text, title):
    assert title in _wording(text)


def test_subject_is_scanned():
    assert "Urgency pressure" in _wording("hello", subject="URGENT: action needed")


def test_each_category_counts_once():
    found = _wording("urgent urgent URGENT immediately act now " * 5)
    assert found == {"Urgency pressure": 10}


def test_phrase_split_across_lines():
    assert "Threatening language" in _wording("your account will be\nsuspended")


@pytest.mark.parametrize("text", [
    "Hi Lavie, your order has shipped. Track it in your account.",
    "Thanks for your purchase! See you next time.",
    "A new public key was added to your account.",
    "We're urgently hiring?",          # 'urgent' needs a whole word
])
def test_normal_text_is_clean(text):
    assert _wording(text) == {}


def test_phishing_sample_wording():
    found = _wording_from("samples/phishing_paypal.eml")
    assert set(found) == {"Threatening language", "Urgency pressure", "Generic greeting",
                          "Requests credentials or personal details"}


def test_legit_sample_wording():
    assert _wording_from("samples/legit_github.eml") == {}


def _wording_from(path):
    return {f.title: f.points for f in check_wording(parse_email(open(path).read()))}
