## What this PR changes

<!-- 1-3 sentences. Link the issue: Closes #12 -->

## How I tested it in the lab

<!-- Be concrete: which alert or command, what was visible in Wazuh, Shuffle, TheHive. Screenshots are welcome - without keys, e-mails or public IPs. -->

## Checklist

- [ ] No passwords, API keys, tokens, cookies or webhook URLs / IDs (exports cleaned with `scripts/sanitize_export.py`)
- [ ] No personal data: real e-mails, our public IP, real user names in paths
- [ ] Screenshots checked with `scripts/check_images.py --ocr` **and** looked at by me
- [ ] Files uploaded through the browser were checked locally first (browser uploads skip the pre-commit hooks)
- [ ] All CI checks are green
- [ ] Documentation updated (README / runbook / ADR), if relevant
