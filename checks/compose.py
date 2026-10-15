"""docker-compose security checks (HS-C01 … HS-C06).

Every check works on the parsed compose structure. Secret VALUES are never
included in any finding — only variable names and locations.
"""

import re

from . import Finding

# container_port -> service name, for ports that should never face the LAN
SENSITIVE_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}

# Well-known default credentials. Compared case-insensitively; the VALUE is
# never printed, only the variable name.
DEFAULT_CREDENTIALS = {
    "password",
    "changeme",
    "admin",
    "administrator",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "welcome",
    "root",
    "toor",
    "test",
    "default",
    "passw0rd",
    "abc123",
    "secret",
}


def _service_env(service):
    env = service.get("environment") or {}
    result = {}
    if isinstance(env, dict):
        for key, value in env.items():
            result[str(key)] = "" if value is None else str(value)
    elif isinstance(env, list):
        for item in env:
            text = str(item)
            if "=" in text:
                key, _, value = text.partition("=")
                result[key.strip()] = value
            else:
                result[text.strip()] = ""
    return result


def _parse_published_ports(ports):
    """Yield (host_ip_or_None, host_port_or_None, container_port_or_None)."""
    for entry in ports or []:
        if isinstance(entry, dict):  # long syntax
            yield (entry.get("host_ip"), entry.get("published"), entry.get("target"))
            continue
        spec = str(entry).strip().strip("\"'")
        spec = re.sub(r"/(tcp|udp|sctp)$", "", spec)
        m = re.match(r"^\[([^\]]+)\]:(\d+):(\d+)$", spec)  # [::1]:8080:80
        if m:
            yield (m.group(1), int(m.group(2)), int(m.group(3)))
            continue
        parts = spec.split(":")
        if len(parts) == 3:  # 127.0.0.1:8080:80
            ip, host_port, container_port = parts
            yield (
                ip or None,
                int(host_port) if host_port.isdigit() else None,
                int(container_port) if container_port.isdigit() else None,
            )
        elif len(parts) == 2:  # 8080:80
            host_port, container_port = parts
            yield (
                None,
                int(host_port) if host_port.isdigit() else None,
                int(container_port) if container_port.isdigit() else None,
            )
        elif len(parts) == 1 and parts[0].isdigit():  # 80 (random host port)
            yield (None, None, int(parts[0]))


def _volume_source(volume):
    if isinstance(volume, dict):  # long syntax
        return str(volume.get("source") or "")
    return str(volume).split(":")[0].strip()


def check_compose(compose_data, compose_path):
    findings = []
    services = (compose_data or {}).get("services") or {}
    if not isinstance(services, dict):
        return findings

    for name, service in services.items():
        if not isinstance(service, dict):
            continue
        location = "%s → services.%s" % (compose_path, name)

        # HS-C01: privileged mode
        if service.get("privileged") is True:
            findings.append(
                Finding(
                    "HS-C01",
                    "critical",
                    "Container '%s' runs in privileged mode" % name,
                    location,
                    "privileged: true disables almost all container isolation. "
                    "A process breakout gives full host access.",
                    "Remove 'privileged: true'. If you need specific "
                    "capabilities, grant only those:\n"
                    "  cap_add:\n"
                    "    - NET_ADMIN",
                )
            )

        # HS-C02: user directive
        user = service.get("user")
        user_text = "" if user is None else str(user).strip()
        if user_text == "":
            findings.append(
                Finding(
                    "HS-C02",
                    "medium",
                    "Container '%s' has no 'user:' directive (runs as root)" % name,
                    location,
                    "Without 'user:', the container process runs as UID 0. "
                    "Combined with a volume mount or breakout, that is host "
                    "root.",
                    "Pin a non-root user:\n"
                    '  user: "1000:1000"   # or a dedicated app user',
                )
            )
        elif user_text in ("0", "root", "0:0", "0:root"):
            findings.append(
                Finding(
                    "HS-C02",
                    "high",
                    "Container '%s' explicitly runs as root" % name,
                    location,
                    "'user: %s' keeps the container process as UID 0." % user_text,
                    "Switch to a non-root user:\n"
                    '  user: "1000:1000"',
                )
            )

        # HS-C03: sensitive ports bound to all interfaces
        exposed = []
        for host_ip, _host_port, container_port in _parse_published_ports(
            service.get("ports")
        ):
            if container_port in SENSITIVE_PORTS and (
                not host_ip or host_ip in ("0.0.0.0", "::")
            ):
                exposed.append(
                    "%d (%s)" % (container_port, SENSITIVE_PORTS[container_port])
                )
        if exposed:
            findings.append(
                Finding(
                    "HS-C03",
                    "high",
                    "Sensitive port(s) exposed to the whole network on '%s'" % name,
                    location,
                    "Published %s with no host-IP bind, so it listens on "
                    "0.0.0.0 — reachable from your entire LAN (and the "
                    "internet, if your router forwards it)."
                    % ", ".join(exposed),
                    "Bind to localhost unless the LAN genuinely needs it:\n"
                    '  ports:\n    - "127.0.0.1:5432:5432"',
                )
            )

        # HS-C04: dangerous bind mounts
        for volume in service.get("volumes") or []:
            source = _volume_source(volume)
            if source == "/var/run/docker.sock":
                findings.append(
                    Finding(
                        "HS-C04",
                        "critical",
                        "Docker socket mounted into '%s'" % name,
                        location,
                        "The Docker socket is root-equivalent: any process "
                        "that can write to it can start a privileged "
                        "container and own the host.",
                        "Do not mount the Docker socket. If a tool needs it "
                        "(e.g. a reverse proxy), use a socket proxy with a "
                        "read-only, filtered socket instead.",
                    )
                )
            elif source and source.rstrip("/") == "":
                findings.append(
                    Finding(
                        "HS-C04",
                        "critical",
                        "Host root filesystem mounted into '%s'" % name,
                        location,
                        "Mounting '/' gives the container read/write access "
                        "to the entire host filesystem.",
                        "Mount only the directories the app needs:\n"
                        "  volumes:\n"
                        "    - app-data:/data   # named volume, not the host root",
                    )
                )

        # HS-C05: restart policy
        restart = service.get("restart")
        restart_text = "" if restart is None else str(restart).strip().lower()
        if restart is None or restart is False or restart_text in ("", "no", "none"):
            findings.append(
                Finding(
                    "HS-C05",
                    "low",
                    "Container '%s' has no restart policy" % name,
                    location,
                    "Without a restart policy the container stays down after "
                    "a crash or host reboot — a silent outage.",
                    "Add a restart policy:\n  restart: unless-stopped",
                )
            )

        # HS-C06: default credentials (names only — values never printed)
        weak_vars = [
            var
            for var, value in _service_env(service).items()
            if value.strip().lower() in DEFAULT_CREDENTIALS
        ]
        if weak_vars:
            findings.append(
                Finding(
                    "HS-C06",
                    "high",
                    "Default credential(s) in '%s'" % name,
                    location,
                    "Environment variable(s) %s use well-known default "
                    "value(s). These are the first values automated scanners "
                    "try. (Values are never displayed by this tool.)"
                    % ", ".join("'%s'" % var for var in weak_vars),
                    "Generate a real secret and keep it out of the compose "
                    "file:\n"
                    "  # shell: openssl rand -base64 32\n"
                    "  environment:\n"
                    "    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}  # from .env",
                )
            )

    return findings
