# Shuffle workflows

Target workflow: `Webhook → normalize → cortex_run → cortex_report → misp_lookup → decide → thehive_alert`.

## Exporting a workflow (always sanitise!)

1. Shuffle → Workflows → ⋮ → **Export** → save as `triage.raw.json` (`*.raw.json` is git-ignored).
2. Sanitise:
   ```bash
   python3 scripts/sanitize_export.py triage.raw.json -o soar/shuffle/workflows/triage.json
   python3 scripts/sanitize_export.py --check soar/
   ```
3. Review the diff by eye, then commit.

After importing a workflow from this repo, re-select the authentication for each app (keys are never stored here).
