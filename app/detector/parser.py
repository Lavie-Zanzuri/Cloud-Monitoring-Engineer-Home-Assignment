"""Turn raw email text into a ParsedEmail.

Supports two kinds of input:
  1. A full RFC 822 / MIME message (.eml, Gmail "Show original").
  2. Plain pasted text with no headers - then we only analyse the body.

Only the Python standard library is used, so the parser has no external
dependencies to install or keep patched.
"""
from __future__ import annotations

import re
from email import policy
from email.message import EmailMessage
from email.parser import Parser
from email.utils import parseaddr
from html import unescape
from html.parser import HTMLParser

from .models import Attachment, Link, ParsedEmail

# A message "has headers" if its first non-empty line looks like "Header-Name: value".
_HEADER_LINE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*:(\s|$)")
# Headers that (almost) every real email carries. Seeing one of them in the
# header block is what convinces us the input is a full email, not pasted text.
_KNOWN_HEADERS = {"from", "to", "subject", "date", "reply-to", "return-path",
                  "received", "delivered-to", "message-id", "mime-version",
                  "content-type"}

# URLs written directly in text (not inside an <a> tag).
_URL_IN_TEXT = re.compile(r"""(?:https?://|www\.)[^\s<>"')\]]+""", re.IGNORECASE)

# "spf=fail", "dkim=pass", "dmarc=none" inside Authentication-Results.
_AUTH_RESULT = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


class _LinkExtractor(HTMLParser):
    """Collects every <a href="...">visible text</a> and the page's plain text."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self.text_parts: list[str] = []
        self._current_href: str | None = None
        self._current_text: list[str] = []
        self._skip = 0  # inside <script>/<style>

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            self._current_href = dict(attrs).get("href") or ""
            self._current_text = []

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._current_href is not None:
            text = " ".join("".join(self._current_text).split())
            self.links.append(Link(url=self._current_href.strip(), display_text=text))
            self._current_href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_parts.append(data)
        if self._current_href is not None:
            self._current_text.append(data)


def _looks_like_email_with_headers(raw: str) -> bool:
    """True if the text starts with a block of 'Name: value' lines that includes
    at least one header every real email has (From, Subject, Received...).

    We look at the whole header block (until the first blank line), not just the
    first line, because exported emails often start with Delivered-To, ARC-Seal etc.
    """
    names: set[str] = set()
    found_blank_line = False
    for line in raw.lstrip().splitlines():
        if not line.strip():          # blank line = end of headers
            found_blank_line = True
            break
        if line[0] in " \t":          # folded continuation of the previous header
            continue
        if not _HEADER_LINE.match(line):
            return False              # a non-header line before the blank line
        names.add(line.split(":", 1)[0].lower())
    # RFC 5322: headers always end with a blank line. Without it, this is most
    # likely pasted text that happens to contain "Something: ..." lines.
    return found_blank_line and bool(names & _KNOWN_HEADERS)


def _html_to_text_and_links(html: str) -> tuple[str, list[Link]]:
    extractor = _LinkExtractor()
    extractor.feed(html)
    text = unescape(" ".join(" ".join(extractor.text_parts).split()))
    return text, extractor.links


def _links_from_text(text: str) -> list[Link]:
    return [Link(url=m.group(0).rstrip(".,;:!?"), display_text="")
            for m in _URL_IN_TEXT.finditer(text)]


def _dedupe(links: list[Link]) -> list[Link]:
    seen: set[tuple[str, str]] = set()
    result = []
    for link in links:
        key = (link.url, link.display_text)
        if key not in seen:
            seen.add(key)
            result.append(link)
    return result


def _parse_mime(raw: str) -> ParsedEmail:
    msg: EmailMessage = Parser(policy=policy.default).parsestr(raw)

    from_name, from_address = parseaddr(str(msg.get("From", "")))
    _, reply_to = parseaddr(str(msg.get("Reply-To", "")))
    _, return_path = parseaddr(str(msg.get("Return-Path", "")))

    auth: dict[str, str] = {}
    for header in msg.get_all("Authentication-Results", []) or []:
        for key, value in _AUTH_RESULT.findall(str(header)):
            auth.setdefault(key.lower(), value.lower())

    texts: list[str] = []
    links: list[Link] = []
    attachments: list[Attachment] = []

    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        if filename or disposition == "attachment":
            payload = part.get_payload(decode=True) or b""
            attachments.append(Attachment(filename=filename or "(unnamed)",
                                          content_type=part.get_content_type(),
                                          size=len(payload)))
            continue

        ctype = part.get_content_type()
        if ctype not in ("text/plain", "text/html"):
            continue
        try:
            content = part.get_content()
        except (LookupError, ValueError):  # unknown charset, broken encoding
            content = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")

        if ctype == "text/html":
            text, html_links = _html_to_text_and_links(content)
            texts.append(text)
            links.extend(html_links)
        else:
            texts.append(content)
            links.extend(_links_from_text(content))

    return ParsedEmail(
        from_name=from_name.strip(),
        from_address=from_address.strip().lower(),
        reply_to=reply_to.strip().lower(),
        return_path=return_path.strip().lower(),
        subject=str(msg.get("Subject", "")).strip(),
        body_text="\n".join(t.strip() for t in texts if t.strip()),
        links=_dedupe(links),
        attachments=attachments,
        auth_results=auth,
        has_headers=True,
    )


def _parse_plain(raw: str) -> ParsedEmail:
    """Pasted body text only. HTML is handled too, in case someone pastes markup."""
    if re.search(r"<a\s[^>]*href", raw, re.IGNORECASE):
        text, links = _html_to_text_and_links(raw)
        links += _links_from_text(text)
    else:
        text, links = raw, _links_from_text(raw)
    return ParsedEmail(body_text=text.strip(), links=_dedupe(links), has_headers=False)


def parse_email(raw: str) -> ParsedEmail:
    """Entry point: decide which kind of input we got and parse it."""
    raw = raw.lstrip("﻿")  # strip a UTF-8 BOM if the file has one
    if _looks_like_email_with_headers(raw):
        return _parse_mime(raw)
    return _parse_plain(raw)