import pytest

from detector.checks.attachments import check_attachments
from detector.models import Attachment, ParsedEmail
from detector.parser import parse_email


def _email_with(*filenames):
    return ParsedEmail(attachments=[Attachment(f, "application/octet-stream", 1) for f in filenames])


def _points(email):
    return sum(f.points for f in check_attachments(email))


@pytest.mark.parametrize("name, expected", [
    ("report.pdf", 0),                 # normal document
    ("photo.JPG", 0),                  # case doesn't matter
    ("setup.exe", 30),                 # executable
    ("invoice.pdf.exe", 50),           # executable + double extension
    ("Invoice.PDF.EXE", 50),           # same, upper case
    ("budget.xlsm", 20),               # macro document
    ("contract.docx.docm", 40),        # macro + double extension
    ("files.zip", 10),                 # archive
    ("my.vacation.photos.zip", 10),    # dots in name, but NOT a double extension
    ("README", 0),                     # no extension at all
    ("(unnamed)", 0),
    ("invoice.pdf.exe ", 50),          # trailing space trick
])
def test_single_attachment_points(name, expected):
    assert _points(_email_with(name)) == expected


def test_no_attachments():
    assert check_attachments(ParsedEmail()) == []


def test_multiple_attachments_add_up():
    assert _points(_email_with("a.exe", "b.zip", "c.pdf")) == 40


def test_sample_phishing_email():
    email = parse_email(open("samples/phishing_paypal.eml").read())
    titles = [f.title for f in check_attachments(email)]
    assert titles == ["Dangerous attachment type", "Double file extension"]


def test_legit_sample_has_no_findings():
    email = parse_email(open("samples/legit_github.eml").read())
    assert check_attachments(email) == []
