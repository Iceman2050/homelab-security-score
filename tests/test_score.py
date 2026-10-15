"""Tests for homelab-security-score. No network access anywhere in this suite."""

import json
import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIXTURES = os.path.join(ROOT, "tests", "fixtures")

sys.path.insert(0, ROOT)

from checks import compose, envfiles, nginx, scoring, yaml_subset  # noqa: E402


def _read(name):
    with open(os.path.join(FIXTURES, name), encoding="utf-8") as handle:
        return handle.read()


def _ids(findings):
    return {f.check_id for f in findings}


# --- YAML subset parser -----------------------------------------------------

def test_subset_parser_handles_compose_shapes():
    data = yaml_subset.parse_subset(_read("docker-compose.bad.yml"))
    assert set(data["services"]) == {"db", "web"}
    assert data["services"]["db"]["privileged"] is True
    assert data["services"]["db"]["ports"] == ["5432:5432"]
    env = data["services"]["db"]["environment"]
    assert env["POSTGRES_PASSWORD"] == "changeme"


def test_subset_parser_good_compose():
    data = yaml_subset.parse_subset(_read("docker-compose.good.yml"))
    assert data["services"]["web"]["user"] == "101:101"
    assert data["services"]["db"]["restart"] == "unless-stopped"


def test_load_prefers_pyyaml_when_available():
    # Just assert load() works either way; result must match the subset parser.
    data = yaml_subset.load(_read("docker-compose.bad.yml"))
    assert data["services"]["web"]["image"] == "nginx:latest"


# --- compose checks ----------------------------------------------------------

def test_bad_compose_fires_expected_findings():
    data = yaml_subset.load(_read("docker-compose.bad.yml"))
    findings = compose.check_compose(data, "docker-compose.bad.yml")
    ids = _ids(findings)
    assert "HS-C01" in ids  # privileged
    assert "HS-C02" in ids  # no user:
    assert "HS-C03" in ids  # 5432 on 0.0.0.0
    assert "HS-C04" in ids  # docker.sock + host root
    assert "HS-C05" in ids  # no restart policy
    assert "HS-C06" in ids  # default credential


def test_bad_compose_scores_low():
    data = yaml_subset.load(_read("docker-compose.bad.yml"))
    findings = compose.check_compose(data, "docker-compose.bad.yml")
    score, grade, _ordered = scoring.score_findings(findings)
    assert score < 50
    assert grade == "F"


def test_good_compose_scores_high():
    data = yaml_subset.load(_read("docker-compose.good.yml"))
    findings = compose.check_compose(data, "docker-compose.good.yml")
    assert not [f for f in findings if f.severity in ("critical", "high")]
    score, grade, _ordered = scoring.score_findings(findings)
    assert score >= 90
    assert grade == "A"


def test_localhost_bound_sensitive_port_is_quiet():
    data = yaml_subset.load(_read("docker-compose.good.yml"))
    findings = compose.check_compose(data, "docker-compose.good.yml")
    assert "HS-C03" not in _ids(findings)


def test_explicit_root_user_is_high():
    data = {"services": {"app": {"image": "x", "user": "root"}}}
    findings = compose.check_compose(data, "compose.yml")
    user_findings = [f for f in findings if f.check_id == "HS-C02"]
    assert user_findings and user_findings[0].severity == "high"


def test_long_syntax_ports_and_volumes():
    data = {
        "services": {
            "app": {
                "image": "x",
                "user": "1000",
                "restart": "unless-stopped",
                "ports": [
                    {"target": 5432, "published": 5432, "host_ip": "127.0.0.1"},
                    {"target": 6379, "published": 6379},
                ],
                "volumes": [{"type": "volume", "source": "data", "target": "/data"}],
            }
        }
    }
    findings = compose.check_compose(data, "compose.yml")
    ids = _ids(findings)
    assert "HS-C03" in ids  # 6379 with no host_ip bind
    assert "HS-C04" not in ids


def test_secret_values_never_appear_in_findings():
    data = yaml_subset.load(_read("docker-compose.bad.yml"))
    findings = compose.check_compose(data, "docker-compose.bad.yml")
    cred = [f for f in findings if f.check_id == "HS-C06"][0]
    for text in (cred.title, cred.location, cred.detail, cred.remediation):
        assert "changeme" not in text
    assert "POSTGRES_PASSWORD" in cred.detail  # variable name is fine


# --- nginx checks ------------------------------------------------------------

def test_bad_nginx_fires_expected_findings():
    findings = nginx.check_nginx(_read("nginx.bad.conf"), "nginx.conf")
    ids = _ids(findings)
    assert "HS-N01" in ids  # server_tokens on
    assert "HS-N02" in ids  # missing headers
    assert "HS-N03" in ids  # http without tls
    assert "HS-N04" in ids  # weak protocols


def test_good_nginx_is_quiet():
    findings = nginx.check_nginx(_read("nginx.good.conf"), "nginx.conf")
    assert findings == []


def test_http_to_https_redirect_is_not_flagged():
    text = (
        "server { listen 80; server_name a.example; "
        "return 301 https://$host$request_uri; }"
    )
    findings = nginx.check_nginx(text, "nginx.conf")
    assert "HS-N03" not in _ids(findings)


# --- env file checks ---------------------------------------------------------

def test_env_without_gitignore_is_flagged(tmp_path):
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=s3cret\n")
    findings = envfiles.check_env_files(str(tmp_path), {"services": {}}, "c.yml")
    assert "HS-E01" in _ids(findings)


def test_env_with_gitignore_is_quiet(tmp_path):
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=s3cret\n")
    (tmp_path / ".gitignore").write_text("*.log\n.env\n")
    findings = envfiles.check_env_files(str(tmp_path), {"services": {}}, "c.yml")
    assert "HS-E01" not in _ids(findings)


def test_env_file_reference_is_checked(tmp_path):
    (tmp_path / "secrets.env").write_text("TOKEN=x\n")
    data = {"services": {"app": {"image": "x", "env_file": ["secrets.env"]}}}
    findings = envfiles.check_env_files(str(tmp_path), data, "c.yml")
    assert "HS-E01" in _ids(findings)


# --- CLI ---------------------------------------------------------------------

def _run_cli(*args):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "score.py"), *args],
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_cli_bad_compose_reports_low_score():
    proc = _run_cli("--compose", os.path.join(FIXTURES, "docker-compose.bad.yml"))
    assert proc.returncode == 0
    assert "Homelab Security Score:" in proc.stdout
    assert "(F)" in proc.stdout
    assert "HS-C01" in proc.stdout


def test_cli_good_compose_reports_high_score():
    proc = _run_cli("--compose", os.path.join(FIXTURES, "docker-compose.good.yml"))
    assert proc.returncode == 0
    assert "(A)" in proc.stdout


def test_cli_json_output_is_valid():
    proc = _run_cli(
        "--compose",
        os.path.join(FIXTURES, "docker-compose.bad.yml"),
        "--nginx",
        os.path.join(FIXTURES, "nginx.bad.conf"),
        "--json",
    )
    assert proc.returncode == 0
    payload = json.loads(proc.stdout)
    assert payload["score"] < 50
    assert payload["grade"] == "F"
    assert any(f["check_id"] == "HS-N03" for f in payload["findings"])


def test_cli_missing_file_exits_nonzero():
    proc = _run_cli("--compose", os.path.join(FIXTURES, "nope.yml"))
    assert proc.returncode != 0


def test_cli_never_prints_secret_values():
    proc = _run_cli(
        "--compose", os.path.join(FIXTURES, "docker-compose.bad.yml"), "--json"
    )
    assert "changeme" not in proc.stdout
