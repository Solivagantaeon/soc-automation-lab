# n8n deployment files



| File | Purpose | Location on the VM |
|---|---|---|
| `compose.yml` | Defines the stack: Caddy (HTTPS proxy), n8n main, n8n worker, task runner, PostgreSQL and Redis, with networks, volumes, healthchecks and memory limits | `/opt/n8n/compose.yml` |
| `Caddyfile` | HTTPS reverse proxy for n8n: certificates from Caddy's internal CA (by hostname and by IP), HTTP → HTTPS redirect, access log with the webhook token removed | `/opt/n8n/Caddyfile` (mounted read-only into the `caddy` container) |
| `make-env.sh` | Generates `.env` (mode 600) with pinned versions, addressing and random secrets; never overwrites an existing `.env`, prints only variable names and checks the result with `docker compose config -q` | `/opt/n8n/make-env.sh` (root only, mode 700) |
| `soc-queue-smoke-test.json` | Test workflow (Webhook → Code → Respond to Webhook) that echoes the posted JSON; proves the path webhook → queue → worker → runner works (runbook step 8.2) | `/opt/n8n/soc-queue-smoke-test.json` |

## Values to change on another environment

| Variable | Our lab | Meaning |
|---|---|---|
| `N8N_HOST` | `n8n.lab` | DNS name of the n8n server; used for the editor and webhook URLs, and as a site address in the Caddyfile (DNS name on the certificate) |
| `N8N_IP` | `10.10.20.249` | IP of the VM; second site address in the Caddyfile and its `default_sni`, so clients connecting by IP get a certificate for the IP |
| `TZ` | `Europe/Warsaw` | Time zone for n8n and PostgreSQL |
| `N8N_WORKER_CONCURRENCY` | `10` | How many executions the worker runs in parallel |
| `N8N_VERSION` | `2.44.6` | Tag of `n8nio/n8n` and `n8nio/runners` (must be the same for both) |
| `POSTGRES_VERSION` | `17.11` | PostgreSQL image tag |
| `REDIS_VERSION` | `7.4.11-alpine` | Redis image tag |
| `CADDY_VERSION` | `2.11.7-alpine` | Caddy image tag |

The lab values are the defaults in `make-env.sh`. On another environment, pass your own values when you run it; there is no need to edit the script:

```bash
sudo N8N_HOST=n8n.example.test N8N_IP=192.0.2.10 TZ=UTC ./make-env.sh
```

The script generates `POSTGRES_PASSWORD`, `N8N_ENCRYPTION_KEY` and `N8N_RUNNERS_AUTH_TOKEN` randomly; do not set them by hand. Back up `N8N_ENCRYPTION_KEY` (or the whole `.env`) to a password manager. Without it, stored credentials cannot be decrypted, even from a database backup. To change a value after `.env` exists, edit `.env` itself; the script never overwrites it.

## Checksums of the deployed files

```text
361cb570ddb4a248092dbc9fa123d5c36b4e33e18668425ffc156969a0caed4d  compose.yml
c99466d3a5e7696404ccff99b724678c11baea5098fa780f78da629a177dc7ed  Caddyfile
cddf79baabd2dbea601cf377e5665bc02a57777f7350dbe0f2b5ef18e49823d5  make-env.sh
```
