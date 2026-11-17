"""All checks share one signature: (ParsedEmail) -> list[Finding].
Adding a check = write the function and add it to ALL_CHECKS."""
from .attachments import check_attachments
from .links import check_links
from .sender import check_sender
from .wording import check_wording

ALL_CHECKS = (check_sender, check_links, check_wording, check_attachments)
