"""Edge cases that real-world emails contain. Each test documents one behaviour."""
import base64

from detector.parser import parse_email


def test_multipart_alternative_text_and_html():
    # Most real emails send the same body twice: text/plain AND text/html.
    raw = (
        "From: Shop <news@shop.com>\nSubject: Sale\nMIME-Version: 1.0\n"
        'Content-Type: multipart/alternative; boundary="b"\n\n'
        "--b\nContent-Type: text/plain\n\nVisit https://shop.com/sale\n"
        '--b\nContent-Type: text/html\n\n<a href="https://shop.com/sale">Visit</a>\n'
        "--b--\n"
    )
    e = parse_email(raw)
    urls = [l.url for l in e.links]
    assert "https://shop.com/sale" in urls
    assert e.attachments == []


def test_base64_encoded_body():
    body = base64.b64encode(b"Click http://evil.example/login now").decode()
    raw = (
        "From: a@b.com\nSubject: x\nMIME-Version: 1.0\n"
        "Content-Type: text/plain; charset=utf-8\nContent-Transfer-Encoding: base64\n\n"
        f"{body}\n"
    )
    e = parse_email(raw)
    assert "Click" in e.body_text
    assert e.links[0].url == "http://evil.example/login"


def test_quoted_printable_html_link():
    # QP encoding breaks long lines with "=" and encodes "=" as "=3D".
    raw = (
        "From: a@b.com\nSubject: x\nMIME-Version: 1.0\n"
        "Content-Type: text/html\nContent-Transfer-Encoding: quoted-printable\n\n"
        '<a href=3D"https://very-long-domain-name.example/path?a=3D1&amp;b=3D2">Ope=\nn</a>\n'
    )
    e = parse_email(raw)
    assert e.links[0].url == "https://very-long-domain-name.example/path?a=1&b=2"
    assert e.links[0].display_text == "Open"


def test_hebrew_encoded_subject_and_sender_name():
    raw = (
        "From: =?UTF-8?B?15HXoNenINeU16TXldei15zXmded?= <info@bank.co.il>\n"
        "Subject: =?UTF-8?B?15PXl9eV16M=?=\n\nhello\n"
    )
    e = parse_email(raw)
    assert e.from_name == "בנק הפועלים"
    assert e.subject == "דחוף"
    assert e.from_address == "info@bank.co.il"


def test_crlf_line_endings():
    raw = "From: a@b.com\r\nSubject: hi\r\n\r\nGo to https://x.com/a\r\n"
    e = parse_email(raw)
    assert e.has_headers
    assert e.links[0].url == "https://x.com/a"


def test_received_header_first():
    # Real exported emails usually start with Received / Delivered-To, not From.
    raw = ("Delivered-To: me@gmail.com\nReceived: from x by y\nFrom: a@b.com\n"
           "Subject: s\n\nbody\n")
    e = parse_email(raw)
    assert e.has_headers
    assert e.from_address == "a@b.com"


def test_inline_image_is_not_an_attachment_without_filename():
    raw = (
        "From: a@b.com\nSubject: x\nMIME-Version: 1.0\n"
        'Content-Type: multipart/related; boundary="b"\n\n'
        "--b\nContent-Type: text/html\n\n<p>hi</p>\n"
        "--b\nContent-Type: image/png\nContent-ID: <logo>\nContent-Disposition: inline\n"
        "Content-Transfer-Encoding: base64\n\niVBORw0KGgo=\n--b--\n"
    )
    e = parse_email(raw)
    assert e.attachments == []


def test_plain_text_that_starts_with_a_colon_phrase_is_not_headers():
    e = parse_email("Hello: please verify your account at http://bad.example\n")
    assert not e.has_headers
    assert e.links[0].url == "http://bad.example"


def test_url_trailing_punctuation_and_parentheses():
    e = parse_email("See (http://a.example/x). Also www.b.example, ok!")
    assert [l.url for l in e.links] == ["http://a.example/x", "www.b.example"]


def test_empty_input_does_not_crash():
    e = parse_email("")
    assert e.body_text == "" and e.links == []


def test_unknown_charset_does_not_crash():
    raw = ("From: a@b.com\nSubject: x\nMIME-Version: 1.0\n"
           "Content-Type: text/plain; charset=x-made-up\n\nhello http://a.example\n")
    e = parse_email(raw)
    assert "hello" in e.body_text


def test_forwarded_email_attachment_message_rfc822():
    raw = (
        "From: a@b.com\nSubject: Fwd\nMIME-Version: 1.0\n"
        'Content-Type: multipart/mixed; boundary="b"\n\n'
        "--b\nContent-Type: text/plain\n\nsee below\n"
        "--b\nContent-Type: message/rfc822\n\n"
        "From: evil@x.ru\nSubject: inner\n\nclick http://inner.example\n--b--\n"
    )
    e = parse_email(raw)
    # outer sender is kept; inner link is still found
    assert e.from_address == "a@b.com"
    assert any(l.url == "http://inner.example" for l in e.links)


def test_display_name_with_email_inside_it():
    # Classic spoofing trick: the display name itself contains a trusted address.
    e = parse_email('From: "support@paypal.com" <x@evil.ru>\nSubject: s\n\nbody\n')
    assert e.from_name == "support@paypal.com"
    assert e.from_address == "x@evil.ru"
