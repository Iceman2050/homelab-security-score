"""Weighted scoring: 100 minus deductions, graded A–F."""

from . import SEVERITY_ORDER, SEVERITY_WEIGHTS


def score_findings(findings):
    score = 100
    for finding in findings:
        score -= SEVERITY_WEIGHTS[finding.severity]
    score = max(0, score)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    ordered = sorted(
        findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.check_id)
    )
    return score, grade, ordered
