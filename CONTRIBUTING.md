# How we work in this repository

In short: **nothing reaches `main` without a pull request**, **no secrets in the repository**, every change is tested.

## 1. First setup (once, on your computer)

```bash
git clone <repo-url>
cd soc-automation-lab
pip install pre-commit                                          # or: pipx install pre-commit
pre-commit install --hook-type pre-commit --hook-type pre-push  # checks before every commit and push
```

Test: `pre-commit run --all-files` → everything "Passed".

Use your **GitHub no-reply address** in git, not a private e-mail: the author address is public in every commit. You find it in GitHub → **Settings → Emails**; also tick *Keep my email addresses private* and *Block command line pushes that expose my email* there. Commits still count towards your profile.

```bash
git config user.name  "First Last"   # or your login - this is public too
git config user.email "<id>+<login>@users.noreply.github.com"
```

## 2. Daily workflow

1. Take a task from **Issues** (or create one) and assign yourself.
2. Create a branch from the current `main`:
```bash
   git switch main && git pull
   git switch -c feat/12-shuffle-cortex-step   # type/issue-number-short-description
```
   Branch types: `feat/`, `fix/`, `docs/`, `detection/`, `chore/`.
3. Commit in small steps. Message format:
```
   feat(shuffle): add cortex_run step to the triage workflow
   fix(wazuh): change the integration filter to rule_id 86601
   docs: describe the MISP configuration in TheHive
```
4. `git push -u origin <branch>` → open a **Pull Request** to `main` and fill in the template.
5. At least one team member reviews it. After approval: **Squash and merge**.

## 3. Secrets (the most important rules)

The repository is public. Anything that reaches the git history stays there forever - even if you delete the file later.

**We never commit:**
- passwords, API keys (Wazuh, Cortex, TheHive, MISP, Shuffle), tokens, session cookies,
- private keys (WireGuard, SSH, TLS certificates),
- Shuffle webhook URLs (anyone who knows the URL can run the workflow),
- the public IP address of the home network or router credentials,
- `credentials.txt`, `.env`, VM backups, memory dumps.

**Instead:** placeholders like `<CORTEX_API_KEY>` and the `.env.example` file.

**Shuffle workflow exports and `ossec.conf` snippets** always go through the script:

```bash
python3 scripts/sanitize_export.py export.json -o soar/shuffle/workflows/soc-automation-v1.0.json
python3 scripts/sanitize_export.py --check .   # must report 0 findings
```

**Uploading a file through the browser ("Add files via upload")?** The pre-commit hooks do not run then, and the commit is public at once. Check the file on your computer first: `python3 scripts/sanitize_export.py --check file`, and a screenshot: `python3 scripts/check_images.py --ocr screenshot.png`. Details, the private `.leakcheck-local` list (your IP, surname) and what to do after a leak: [SECURITY.md](SECURITY.md).

On Windows type `python` instead of `python3`. Look at the diff yourself anyway - the scripts catch typical cases, not all of them.

**If a secret does reach the repository:** tell the team channel immediately and **change / revoke the key in its system** (that is the real fix); only then do we clean up the history.

## 4. Where things go

| What | Where |
|---|---|
| Wazuh rules and decoders | `detection/wazuh/rules/`, `detection/wazuh/decoders/` |
| Agent configuration (`agent.conf`) | `detection/wazuh/agent-config/` |
| `ossec.conf` snippets (integrations) | `detection/wazuh/integrations/` |
| Shuffle workflows (JSON, sanitised) | `soar/shuffle/workflows/` |
| Sample alerts for testing | `samples/alerts/` (synthetic or anonymised) |
| Normalised alerts and enrichment results | `samples/normalized/` |
| Alert-funnel measurements | `metrics/` |
| Architecture decisions | `docs/decisions/` (ADR format, copy `0000-template.md`) |
| Step-by-step instructions | `docs/runbooks/` |
| Screenshots | `docs/images/<component>/` (check them with `check_images.py` and by eye!) |

## 5. Definition of done

- [ ] change tested in the lab (test described in the PR),
- [ ] documentation updated (README / runbook / ADR),
- [ ] `pre-commit run --all-files` passes,
- [ ] reviewed by at least one person.

## 6. Language

The whole repository is in **English**: documentation, comments in code and configuration, commits, branch names, issues and pull requests. We speak Polish only on the team channel.
