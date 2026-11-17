import json
import subprocess
import sys

import pytest

from detector.analyzer import analyze
from detector.models import Finding
from detector.scorer import score_findings, verdict_for


def F(category, points):
    return Finding(category, "t", "d", points)


@pytest.mark.parametrize("score, verdict", [
    (0, "Safe"), (24, "Safe"), (25, "Suspicious"), (59, "Suspicious"),
    (60, "Phishing"), (100, "Phishing"),
])
def test_thresholds(score, verdict):
    assert verdict_for(score) == verdict


def test_no_findings_is_safe():
    r = score_findings([])
    assert (r.score, r.verdict) == (0, "Safe")


def test_one_category_is_capped_and_cannot_reach_phishing_alone():
    r = score_findings([F("links", 35), F("links", 30), F("links", 30)])
    assert r.score == 50 and r.verdict == "Suspicious"


def test_two_categories_can_reach_phishing():
    assert score_findings([F("links", 35), F("sender", 35)]).verdict == "Phishing"


def test_total_is_capped_at_100():
    findings = [F(c, 50) for c in ("links", "sender", "wording", "attachments")]
    assert score_findings(findings).score == 100


@pytest.mark.parametrize("path, verdict", [
    ("samples/phishing_paypal.eml", "Phishing"),
    ("samples/plain_text_phish.txt", "Phishing"),
    ("samples/legit_github.eml", "Safe"),
])
def test_samples_end_to_end(path, verdict):
    assert analyze(open(path).read()).verdict == verdict


def test_findings_sorted_strongest_first():
    pts = [f.points for f in analyze(open("samples/phishing_paypal.eml").read()).findings]
    assert pts == sorted(pts, reverse=True)


def _run_cli(*args):
    return subprocess.run([sys.executable, "cli.py", *args], capture_output=True, text=True)


def test_cli_exit_codes():
    assert _run_cli("samples/legit_github.eml").returncode == 0
    assert _run_cli("samples/phishing_paypal.eml").returncode == 2
    assert _run_cli("does/not/exist.eml").returncode == 3


def test_cli_json_output():
    data = json.loads(_run_cli("samples/phishing_paypal.eml", "--json").stdout)
    assert data["verdict"] == "Phishing" and data["score"] == 100
    assert {"category", "title", "detail", "points"} <= set(data["findings"][0])
