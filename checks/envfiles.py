"""Secret-file hygiene checks (HS-E01).

Heuristic: a .env-style file present on disk that is NOT covered by
.gitignore is one accidental 'git add .' away from a public repo.
"""

import fnmatch
import os

from . import Finding

IGNORE_PATTERNS = {".env", "*.env", ".env*", "**/.env", ".env.*", "*.env.*"}


def _gitignore_covers(gitignore_path, filename):
    try:
        with open(gitignore_path, "r", encoding="utf-8", errors="replace") as handle:
            patterns = [
                line.strip()
                for line in handle
                if line.strip() and not line.strip().startswith("#")
            ]
    except OSError:
        return False
    for pattern in patterns:
        candidate = pattern.lstrip("/").rstrip("/")
        if candidate in IGNORE_PATTERNS:
            return True
        if fnmatch.fnmatch(filename, candidate):
            return True
    return False


def _is_env_file(name):
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def check_env_files(project_dir, compose_data, compose_path):
    findings = []
    try:
        entries = os.listdir(project_dir or ".")
    except OSError:
        return findings

    candidates = {entry for entry in entries if _is_env_file(entry)}

    # env_file: references in the compose file
    services = (compose_data or {}).get("services") or {}
    if isinstance(services, dict):
        for _name, service in services.items():
            if not isinstance(service, dict):
                continue
            env_file = service.get("env_file")
            refs = (
                env_file
                if isinstance(env_file, list)
                else [env_file]
                if env_file
                else []
            )
            for ref in refs:
                if isinstance(ref, dict):
                    path = ref.get("path")
                else:
                    path = ref
                if not path:
                    continue
                full = os.path.join(project_dir or ".", str(path))
                if os.path.isfile(full):
                    candidates.add(os.path.basename(str(path)))

    gitignore_path = os.path.join(project_dir or ".", ".gitignore")
    for filename in sorted(candidates):
        if not _gitignore_covers(gitignore_path, filename):
            findings.append(
                Finding(
                    "HS-E01",
                    "high",
                    "Secret file '%s' is not gitignored" % filename,
                    os.path.join(project_dir or ".", filename),
                    "'%s' exists on disk but no .gitignore rule covers it. "
                    "One 'git add .' and your secrets are in version "
                    "control — and possibly a public repo." % filename,
                    "Ignore it before the next commit:\n"
                    "  echo '.env' >> .gitignore\n"
                    "  # then verify: git check-ignore -v %s" % filename,
                )
            )
    return findings
