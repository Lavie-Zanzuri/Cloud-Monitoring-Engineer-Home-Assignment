"""The single entry point used by the CLI, the web API and (later) the Gmail add-on."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

from .checks import ALL_CHECKS
from .models import Finding
from .parser import parse_email
from .scorer import score_findings


@dataclass
class AnalysisResult:
    verdict: str
    score: int
    from_address: str
    from_name: str
    subject: str
    findings: list[Finding] = field(default_factory=list)
    category_scores: dict[str, int] = field(default_factory=dict)

    @property
    def is_phishing(self) -> bool:
        return self.verdict == "Phishing"

    def to_dict(self) -> dict:
        return asdict(self)


def analyze(raw_email: str) -> AnalysisResult:
    email = parse_email(raw_email)
    findings = [finding for check in ALL_CHECKS for finding in check(email)]
    findings.sort(key=lambda f: f.points, reverse=True)   # strongest evidence first
    scored = score_findings(findings)
    return AnalysisResult(
        verdict=scored.verdict,
        score=scored.score,
        from_address=email.from_address,
        from_name=email.from_name,
        subject=email.subject,
        findings=findings,
        category_scores=scored.category_scores,
    )
