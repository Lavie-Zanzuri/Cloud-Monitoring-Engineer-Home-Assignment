import unittest

from detector.models import Attachment, Link, ParsedEmail
from detector.parser import parse_email


class TestEmailParser(unittest.TestCase):
    def test_empty_or_whitespace_input(self):
        for raw in ("", " \t\r\n"):
            with self.subTest(raw=raw):
                self.assertEqual(parse_email(raw), ParsedEmail())

    def test_header_like_text_is_preserved_in_plain_body(self):
        raw = "Reminder: update your account\nSubject: Action required"
        self.assertEqual(parse_email(raw), ParsedEmail(body_text=raw))

    def test_bom_and_crlf_before_mime_headers(self):
        raw = "\ufeffFrom: Support <HELP@EXAMPLE.COM>\r\nSubject: Update\r\n\r\nHello\r\n"
        parsed = parse_email(raw)

        self.assertTrue(parsed.has_headers)
        self.assertEqual(parsed.from_name, "Support")
        self.assertEqual(parsed.from_address, "help@example.com")
        self.assertEqual(parsed.subject, "Update")
        self.assertEqual(parsed.body_text, "Hello")

    def test_missing_mime_headers_and_empty_body(self):
        self.assertEqual(
            parse_email("Subject: Empty message\n\n"),
            ParsedEmail(subject="Empty message", has_headers=True),
        )

    def test_plain_links_remove_trailing_punctuation_and_duplicates(self):
        raw = "See (https://example.com/a), https://example.com/a! Or www.example.org."
        self.assertEqual(
            parse_email(raw).links,
            [Link("https://example.com/a", ""), Link("www.example.org", "")],
        )

    def test_html_keeps_link_target_and_visible_text_separate(self):
        raw = (
            "Content-Type: text/html; charset=utf-8\n\n"
            '<a href="http://192.0.2.1/login?a=1&amp;b=2">'
            "https://example.com/login</a>"
        )
        parsed = parse_email(raw)

        self.assertEqual(parsed.body_text, "https://example.com/login")
        self.assertEqual(
            parsed.links,
            [Link("http://192.0.2.1/login?a=1&b=2", "https://example.com/login")],
        )

    def test_pasted_html_ignores_script_and_style_text(self):
        raw = (
            "<script>https://script.example</script>"
            "<style>https://style.example</style>"
            '<a href="https://example.com">Read <b>more</b></a>'
        )
        self.assertEqual(
            parse_email(raw),
            ParsedEmail(
                body_text="Read more",
                links=[Link("https://example.com", "Read more")],
            ),
        )

    def test_same_html_target_with_different_labels_is_preserved(self):
        raw = (
            '<a href="https://example.com">One</a>'
            '<a href="https://example.com">Two</a>'
            '<a href="https://example.com">One</a>'
        )
        self.assertEqual(
            parse_email(raw).links,
            [Link("https://example.com", "One"), Link("https://example.com", "Two")],
        )

    def test_unknown_charset_falls_back_to_utf8(self):
        raw = (
            'Content-Type: text/plain; charset="unknown-charset"\n'
            "Content-Transfer-Encoding: base64\n\n"
            "Y2Fmw6k=\n"
        )
        self.assertEqual(parse_email(raw).body_text, "café")

    def test_unnamed_text_attachment_is_kept_out_of_email_body(self):
        raw = (
            'Content-Type: multipart/mixed; boundary="test"\n\n'
            "--test\nContent-Type: text/plain\n\nHello\n"
            "--test\nContent-Type: text/plain\n"
            "Content-Disposition: attachment\n"
            "Content-Transfer-Encoding: base64\n\n"
            "SGVsbG8=\n--test--\n"
        )
        parsed = parse_email(raw)

        self.assertEqual(parsed.body_text, "Hello")
        self.assertEqual(
            parsed.attachments,
            [Attachment(filename="(unnamed)", content_type="text/plain", size=5)],
        )


if __name__ == "__main__":
    unittest.main()
