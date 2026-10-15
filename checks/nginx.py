"""nginx configuration checks (HS-N01 … HS-N04). Regex-based, no dependencies."""

import re

from . import Finding

REQUIRED_HEADERS = {
    "X-Content-Type-Options": 'add_header X-Content-Type-Options "nosniff" always;',
    "X-Frame-Options": 'add_header X-Frame-Options "SAMEORIGIN" always;',
    "Referrer-Policy": 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;',
    "Content-Security-Policy": 'add_header Content-Security-Policy "default-src \'self\'" always;',
    "Strict-Transport-Security": 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
}

WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}


def _strip_comments(text):
    # Naive but effective for nginx configs (# inside quoted strings is rare).
    return "\n".join(line.split("#", 1)[0] for line in text.splitlines())


def _server_blocks(text):
    """Extract top-level server { ... } blocks via brace matching."""
    blocks = []
    for match in re.finditer(r"(^|[;\}\s])server\s*\{", text):
        start = match.end() - 1  # the opening brace
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    blocks.append(text[start : i + 1])
                    break
    return blocks


def _listens_http_only(block):
    listens = re.findall(r"listen\s+([^;]+);", block)
    has_80 = any(re.search(r"(?<![\d.])80(?![\d.])", entry) for entry in listens)
    has_443_ssl = any(
        re.search(r"\b443\b", entry) and "ssl" in entry.split() for entry in listens
    )
    if not (has_80 and not has_443_ssl):
        return False
    # An http->https redirect block is fine; only flag real HTTP serving.
    if re.search(r"return\s+30[0-9]\s+https://", block):
        return False
    return True


def check_nginx(nginx_text, nginx_path):
    findings = []
    text = _strip_comments(nginx_text or "")

    # HS-N01: server_tokens on
    if re.search(r"server_tokens\s+on\s*;", text):
        findings.append(
            Finding(
                "HS-N01",
                "medium",
                "server_tokens is on (version disclosure)",
                nginx_path,
                "'server_tokens on;' makes nginx advertise its exact "
                "version in responses and error pages — free recon for "
                "attackers matching version to CVE.",
                "Hide the version banner:\n  server_tokens off;",
            )
        )

    # HS-N02: missing security headers
    missing = [
        name
        for name in REQUIRED_HEADERS
        if not re.search(r"add_header\s+" + re.escape(name) + r"\b", text, re.IGNORECASE)
    ]
    if missing:
        snippets = "\n".join("  " + REQUIRED_HEADERS[name] for name in missing)
        findings.append(
            Finding(
                "HS-N02",
                "medium",
                "Missing security header(s): %s" % ", ".join(missing),
                nginx_path,
                "No 'add_header' found for: %s. Missing headers leave "
                "clickjacking, MIME-sniffing, and downgrade attacks on the "
                "table." % ", ".join(missing),
                "Add the missing headers (http, server, or location level):\n"
                + snippets,
            )
        )

    # HS-N03: HTTP served without TLS
    for block in _server_blocks(text):
        server_name = re.search(r"server_name\s+([^;]+);", block)
        name = server_name.group(1).strip() if server_name else "(unnamed server)"
        if _listens_http_only(block):
            findings.append(
                Finding(
                    "HS-N03",
                    "high",
                    "Server '%s' serves HTTP with no TLS" % name,
                    nginx_path,
                    "A server block listens on port 80 with no 'listen 443 "
                    "ssl' and no https redirect — traffic (including logins "
                    "and cookies) crosses the network in cleartext.",
                    "Terminate TLS and redirect plain HTTP:\n"
                    "  server {\n"
                    "    listen 80;\n"
                    "    server_name %s;\n"
                    "    return 301 https://$host$request_uri;\n"
                    "  }" % name,
                )
            )

    # HS-N04: weak ssl_protocols
    for protocols in re.findall(r"ssl_protocols\s+([^;]+);", text):
        tokens = protocols.split()
        weak = [tok for tok in tokens if tok in WEAK_PROTOCOLS]
        if weak:
            findings.append(
                Finding(
                    "HS-N04",
                    "high",
                    "Weak TLS protocol(s) enabled: %s" % ", ".join(weak),
                    nginx_path,
                    "'ssl_protocols %s;' enables protocol versions with "
                    "known cryptographic weaknesses." % protocols.strip(),
                    "Use modern protocols only:\n"
                    "  ssl_protocols TLSv1.2 TLSv1.3;",
                )
            )

    return findings
