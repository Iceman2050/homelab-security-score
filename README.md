[![AI Security Score](https://ingeniousai-security-checks.netlify.app/badges/homelab-security-score.svg)](https://ingeniousai-security-checks.netlify.app/ai-security-badge.html)

# homelab-security-score

Point it at your homelab configs. Get a security score with concrete fixes.

```bash
python3 score.py --compose docker-compose.yml --nginx nginx.conf
```

```
Homelab Security Score: 62/100 (C)

HIGH
  [HS-C03] Sensitive port(s) exposed to the whole network on 'db'
    ...
    Fix:
        ports:
          - "127.0.0.1:5432:5432"
```

## Privacy: your configs never leave your machine

This tool makes **zero network calls** — no uploads, no telemetry, no update
checks, nothing. It reads the files you point it at, scores them locally, and
prints the result. Secret *values* are never printed either: findings name the
variable and the location, never the value.

## Install

No dependencies. Python 3.8+ only.

```bash
git clone https://github.com/Iceman2050/homelab-security-score.git
cd homelab-security-score
python3 score.py --compose /path/to/docker-compose.yml
```

Optional: `pip install pyyaml` — the tool uses PyYAML when available and
falls back to a built-in YAML-subset parser otherwise. The fallback handles
the compose shapes most homelabs use; exotic YAML (anchors, flow style,
multi-line blocks) wants PyYAML.

## Usage

```bash
# compose file only
python3 score.py --compose docker-compose.yml

# compose + nginx
python3 score.py --compose docker-compose.yml --nginx /etc/nginx/nginx.conf

# .env / .gitignore hygiene uses the current directory by default;
# point it at your project explicitly:
python3 score.py --compose docker-compose.yml --project-dir ~/homelab

# machine-readable output
python3 score.py --compose docker-compose.yml --json
```

## What it checks

| ID | Severity | Check |
|----|----------|-------|
| HS-C01 | Critical | `privileged: true` on a container |
| HS-C02 | Medium / High | No `user:` directive (runs as root) / explicitly root |
| HS-C03 | High | Sensitive port (DB, SSH, Redis…) bound to 0.0.0.0 |
| HS-C04 | Critical | `/var/run/docker.sock` or host `/` mounted into a container |
| HS-C05 | Low | No restart policy |
| HS-C06 | High | Well-known default credentials in `environment` (values never shown) |
| HS-N01 | Medium | `server_tokens on` (nginx version disclosure) |
| HS-N02 | Medium | Missing security headers (HSTS, CSP, X-Frame-Options…) |
| HS-N03 | High | HTTP served with no TLS and no https redirect |
| HS-N04 | High | Weak `ssl_protocols` (SSLv3, TLS 1.0/1.1) |
| HS-E01 | High | `.env`-style secret file present but not gitignored |

Scoring: start at 100, deduct 20 per critical, 10 per high, 5 per medium,
2 per low. Grades: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F < 40.

## Honest limitations

- **Static heuristics, not a pentest.** This reads config files; it cannot see
  runtime state, firewall rules, or router port-forwards.
- It flags *likely* problems. A database intentionally exposed to a trusted
  LAN is your call — the finding tells you it is exposed so you decide.
- The built-in YAML parser covers common compose shapes; install PyYAML for
  full YAML support.
- nginx parsing is regex-based; very unusual configs may confuse it.

## Interactive version

Prefer a guided quiz over the CLI? Try the free 2-minute web version (also
private — answers never leave your browser):

**https://ingeniousai-security-checks.netlify.app/homelab-exposure-quiz.html**

## Contributing

PRs welcome. Rules: stdlib only, no network calls ever, never print secret
values, every check needs a fixture test.

## License

MIT — see [LICENSE](LICENSE). © 2026 Ingenious AI.

## Built by Ingenious AI

This project is part of the **Ingenious AI** platform suite — defensive security tooling for the AI era. Our platforms are currently in early access (full launch Nov 1) — request access to any of them on WhatsApp:

- [DisclosureGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DisclosureGuard)
- [ModelMinder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ModelMinder)
- [TermsWatch](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20TermsWatch)
- [Vibe-Code Audit](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Vibe-Code%20Audit)
- [Rogue-Agent Defense](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Rogue-Agent%20Defense)
- [BreachHunter](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20BreachHunter)
- [ChatBreaker](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ChatBreaker)
- [Agent Flight Recorder](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Flight%20Recorder)
- [Agent Auth Gateway](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20Agent%20Auth%20Gateway)
- [DomainGuard](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20DomainGuard)
- [ContentCraft AI](https://wa.me/5016691053?text=Hi%20Ingenious%20AI!%20I%20want%20early%20access%20to%20ContentCraft%20AI)


> Built by Ingenious AI with Muse — get free tokens with invite code `2HCQH1`
