#!/usr/bin/env python3
"""homelab-security-score — local-only security scoring for homelab configs.

Reads your docker-compose.yml (and optionally nginx.conf), runs static
security heuristics, and prints a 0-100 score with prioritized fixes.

Privacy: everything runs on your machine. No network calls, no uploads,
no telemetry. Your configs never leave your machine.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from checks import compose, envfiles, nginx, scoring, yaml_subset  # noqa: E402


def _read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read()
    except OSError as exc:
        print("error: cannot read %s: %s" % (path, exc), file=sys.stderr)
        sys.exit(2)


def _text_report(score, grade, findings, compose_path, nginx_path):
    lines = []
    lines.append("Homelab Security Score: %d/100 (%s)" % (score, grade))
    lines.append("Scanned: %s%s" % (compose_path, ", %s" % nginx_path if nginx_path else ""))
    lines.append("")
    if not findings:
        lines.append("No findings. Nice work — re-run after every config change.")
        return "\n".join(lines)
    current = None
    for finding in findings:
        if finding.severity != current:
            current = finding.severity
            lines.append("%s" % current.upper())
        lines.append("  [%s] %s" % (finding.check_id, finding.title))
        lines.append("    Location: %s" % finding.location)
        lines.append("    %s" % finding.detail)
        lines.append("    Fix:")
        for remedy_line in finding.remediation.splitlines():
            lines.append("      %s" % remedy_line)
        lines.append("")
    return "\n".join(lines).rstrip("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Score your homelab configs for security issues. "
        "100%% local — nothing is uploaded anywhere."
    )
    parser.add_argument("--compose", required=True, help="path to docker-compose.yml")
    parser.add_argument("--nginx", default=None, help="path to nginx.conf (optional)")
    parser.add_argument(
        "--project-dir",
        default=".",
        help="project directory for .env / .gitignore checks (default: .)",
    )
    parser.add_argument(
        "--json", dest="as_json", action="store_true", help="machine-readable output"
    )
    args = parser.parse_args(argv)

    compose_data = yaml_subset.load(_read_file(args.compose))
    findings = compose.check_compose(compose_data, args.compose)

    if args.nginx:
        findings += nginx.check_nginx(_read_file(args.nginx), args.nginx)

    findings += envfiles.check_env_files(args.project_dir, compose_data, args.compose)

    score, grade, ordered = scoring.score_findings(findings)

    if args.as_json:
        print(
            json.dumps(
                {
                    "score": score,
                    "grade": grade,
                    "parser": "pyyaml" if yaml_subset.using_pyyaml() else "builtin",
                    "findings": [finding.to_dict() for finding in ordered],
                },
                indent=2,
            )
        )
    else:
        print(_text_report(score, grade, ordered, args.compose, args.nginx))
    return 0


if __name__ == "__main__":
    sys.exit(main())
