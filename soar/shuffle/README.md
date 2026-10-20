# Shuffle workflows

Target workflow: `Webhook → normalize → cortex_run → cortex_report → misp_lookup → decide → thehive_alert`.

## Exporting a workflow (always sanitise!)

1. Shuffle → Workflows → ⋮ → **Export** → save as `soc-automation.raw.json` (`*.raw.json` is git-ignored).
2. Sanitise:
   ```bash
   python3 scripts/sanitize_export.py soc-automation.raw.json -o soar/shuffle/workflows/soc-automation-v1.0.json
   python3 scripts/sanitize_export.py --check soar/
   ```
   Besides keys and tokens, the script replaces the webhook trigger `id` with `00000000-...`:
   in an export that ID **is** the webhook URL (`/api/v1/hooks/webhook_<id>`).
3. Review the diff by eye, then commit. Never upload the raw export through the browser.

Do not type keys into `http` nodes (e.g. an `Authorization: Bearer ...` header): such a key ends up in
every export. Use the app's saved authentication, or the TheHive app action, instead.

After importing a workflow from this repo, re-select the authentication for each app (keys are never stored here).
