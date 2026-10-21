# Security policy

This repository documents an **isolated, educational home lab**, and it is **public**. Every pushed commit - on any branch, in any pull request - is visible to everyone at once, and it stays in GitHub's history even after the file is deleted or the branch is force-pushed.

## Reporting

If you notice a leaked credential, private key or personal data in this repository or its history, **do not open a public issue**. Use the *Report a vulnerability* button on the Security tab, or contact a maintainer privately.

## What must never be committed

| Kind | Examples |
|---|---|
| Credentials | API keys (TheHive, Cortex, MISP, VirusTotal, AbuseIPDB, Shuffle), passwords, tokens, cookies, `Authorization` headers, private keys, WireGuard keys, Wazuh agent keys, password hashes |
| Shuffle webhooks | `.../api/v1/hooks/webhook_<id>`, and the trigger `id` in a workflow export, which **is** that URL |
| Network data | our public (home) IP address, router details, the VPN endpoint |
| Personal data | real names, personal e-mails, user names in paths (`/Users/<name>`, `C:\Users\<name>`), photos with GPS data |
| Raw lab artefacts | unsanitised exports, `*.bak` config backups, Wazuh installer passwords, OPNsense config backups, HAR files, packet captures, event logs, memory dumps, cracked hashes |

Screenshots count too: look for keys on settings pages, webhook URLs, the logged-in user's e-mail and the browser address bar. Issue and PR comments are just as public, and the checks below do not read them.

## How the repository is protected

| Layer | Where | What it catches | Limits |
|---|---|---|---|
| 1. GitHub push protection | GitHub, also for web uploads | well-known token formats (GitHub, AWS, Slack, ...) | does **not** know TheHive / MISP / Cortex keys or Shuffle webhooks |
| 2. pre-commit hooks | your computer | gitleaks, `sanitize_export.py`, `check_images.py`, every commit you push | only for `git commit` / `git push`, **not** for files uploaded in the browser |
| 3. CI on every push (`checks.yml`) | GitHub Actions | gitleaks over the full history of every branch; secrets and personal data in all files **and in every new commit**; image metadata and OCR of visible text | runs after the push: the data is already public, so rotate |
| 4. Rules on `main` | repository settings | nothing reaches `main` without a pull request, a review and green checks | |
| 5. CODEOWNERS | `.github/CODEOWNERS` | changes to the checks or to the allowlist need the owner's review | |

Layers 2 and 3 share the same rules: `scripts/sanitize_export.py`, `scripts/check_images.py` and `.gitleaks.toml`.

## Before uploading a file through the GitHub web page

Browser uploads skip layer 2 and are public immediately. Before you click *Commit changes*:

1. **Check the file.** Python 3 only, nothing to install; a single downloaded `sanitize_export.py` works too.
   ```bash
   python3 scripts/sanitize_export.py --check path/to/file.json
   ```
2. **Exports and real alerts: upload a cleaned copy.**
   ```bash
   python3 scripts/sanitize_export.py raw-export.json -o clean.json
   ```
   Secrets become `REDACTED`, webhook IDs `00000000-...`, public IPs RFC 5737 addresses, e-mails `userN@example.com` and user names `<user>`. `--keep-pii` keeps IPs and e-mails (secrets are still removed).
3. **Screenshots** (needs `pip install pillow`; OCR also needs tesseract: `brew install tesseract` / `sudo apt install tesseract-ocr`):
   ```bash
   python3 scripts/check_images.py --ocr shot.png     # report
   python3 scripts/check_images.py --strip shot.png   # remove metadata: GPS, camera, computer name
   ```
   OCR is best effort. Look at the picture yourself and crop or blur anything sensitive.

## Your private list: `.leakcheck-local`

Values only you know - your home IP, real name, personal e-mail, router password - can be blocked without publishing them. Create `.leakcheck-local` in the repository root or in your home directory. It is git-ignored and never committed. One value per line:

```text
# my private values, never committed
<your public IP>
<your personal e-mail>
<your surname>
```

The checks then refuse any file or commit that contains one of them, and print it only as `***`.

## Allowlist: `.leakcheck-allow`

For values that look sensitive but are not, such as test IOCs or public CDN addresses in API samples. Every entry needs a reason, and the repository owner reviews each change (CODEOWNERS).

- an IP, CIDR range, e-mail or literal value
- `sha256:<hash> <path>`: a file a human has reviewed, e.g. a screenshot; the entry stops working when the file changes
- `commit:<sha>`: an already-pushed commit whose problem has been handled (secret rotated, file fixed later), because history cannot be changed

**Never paste the sensitive value itself into the allowlist.** It is public.

## Commit e-mail

Every commit publishes the author's e-mail address. Use your GitHub no-reply address:

1. GitHub, **Settings, Emails**: tick **Keep my email addresses private** and **Block command line pushes that expose my email**.
2. Copy the address shown there and set it:
   ```bash
   git config --global user.email "<id>+<login>@users.noreply.github.com"
   ```

Addresses in earlier commits stay in the history.

## If something leaks

1. **Tell the team privately**, not in an issue or a PR comment.
2. **Rotate first**: change the key, password or webhook in the system it belongs to. This is the real fix. Deleting the file or force-pushing does **not** remove it from GitHub: pull-request history, forks, clones and caches keep it.
3. Fix the files in a new commit (`sanitize_export.py`), then acknowledge the old commit in `.leakcheck-allow` with `commit:<sha>  # what was rotated`.
4. Optionally ask GitHub Support to remove cached views of the commit.
