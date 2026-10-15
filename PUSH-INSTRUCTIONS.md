# Push instructions (your one tap)

The repo is fully built and tested locally at
`~/workspace/oss/homelab-security-score/`. Creating the GitHub repo is an
account action, so it needs your tap:

## Option A — GitHub CLI (one command)

```bash
cd ~/workspace/oss/homelab-security-score
git init
git add .
git commit -m "homelab-security-score: local-only homelab config security scorer"
gh repo create ingenious-ai/homelab-security-score --public \
  --description "Point it at your homelab configs, get a security score with fixes. 100% local — your configs never leave your machine." \
  --source=. --push
```

(Replace `ingenious-ai` with your GitHub org/username.)

## Option B — web UI

1. github.com → New repository → name `homelab-security-score`, Public,
   MIT license (already in repo — don't let GitHub add a second one).
2. Then locally:
   ```bash
   cd ~/workspace/oss/homelab-security-score
   git init
   git add .
   git commit -m "homelab-security-score: local-only homelab config security scorer"
   git branch -M main
   git remote add origin https://github.com/<you>/homelab-security-score.git
   git push -u origin main
   ```

## After pushing

- Edit README: replace `YOUR-ORG` in the clone URL with your org/username.
- Add repo topics: `security`, `homelab`, `docker`, `selfhosted`,
  `devsecops`, `nginx`, `privacy`.
- Traffic taps (copy ready in the packets file):
  1. r/homelab — "Project Showcase: Software" flair (AI disclosure in body).
  2. Show HN — "Show HN: Homelab security scorer, 100% local".
  3. TLDR / console.dev tool submission.
  4. awesome-selfhosted PR (selfhosted tooling category).
