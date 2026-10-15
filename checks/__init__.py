"""Shared finding record and severity model for homelab-security-score."""


SEVERITY_WEIGHTS = {
    "critical": 20,
    "high": 10,
    "medium": 5,
    "low": 2,
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class Finding:
    """One security finding. Secret VALUES are never stored here — only names."""

    def __init__(self, check_id, severity, title, location, detail, remediation):
        if severity not in SEVERITY_WEIGHTS:
            raise ValueError("unknown severity: %r" % (severity,))
        self.check_id = check_id
        self.severity = severity
        self.title = title
        self.location = location
        self.detail = detail
        self.remediation = remediation

    def to_dict(self):
        return {
            "check_id": self.check_id,
            "severity": self.severity,
            "title": self.title,
            "location": self.location,
            "detail": self.detail,
            "remediation": self.remediation,
        }
