# Security policy

This repository documents an **isolated, educational home lab**. It contains no production systems and no real credentials.

## Reporting

If you notice something that looks like a leaked credential, a private key, or personal data in this repository or its history, please **do not open a public issue**. Contact the maintainers privately via GitHub's *Report a vulnerability* button (Security tab) or by e-mail listed on a maintainer's profile.

## What we do to prevent leaks

- Every commit is scanned with [gitleaks](https://github.com/gitleaks/gitleaks) (pre-commit hook and CI).
- Exports from Shuffle and Wazuh configuration snippets are sanitised with `scripts/sanitize_export.py` before being committed.
- Any secret that ever reaches the repository is treated as compromised and rotated, regardless of history rewriting.
