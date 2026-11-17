"""Turns findings into one risk score (0-100) and a verdict.

Each category is capped, so ONE kind of evidence can at most reach "Suspicious";
a "Phishing" verdict needs evidence from at least two independent categories.
This keeps a single noisy rule from condemning a legitimate email.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .models import Finding

MAX_SCORE = 100
CATEGORY_CAP = 50
SUSPICIOUS_FROM = 25
PHISHING_FROM = 60

SAFE, SUSPICIOUS, PHISHING = "Safe", "Suspicious", "Phishing"


@dataclass
class ScoreResult:
    score: int
    verdict: str
    category_scores: dict[str, int] = field(default_factory=dict)


def verdict_for(score: int) -> str:
    if score >= PHISHING_FROM:
        return PHISHING
    if score >= SUSPICIOUS_FROM:
        return SUSPICIOUS
    return SAFE


def score_findings(findings: list[Finding]) -> ScoreResult:
    per_category: dict[str, int] = {}
    for f in findings:
        per_category[f.category] = per_category.get(f.category, 0) + f.points
    capped = {cat: min(points, CATEGORY_CAP) for cat, points in per_category.items()}
    score = min(sum(capped.values()), MAX_SCORE)
    return ScoreResult(score=score, verdict=verdict_for(score), category_scores=capped)
