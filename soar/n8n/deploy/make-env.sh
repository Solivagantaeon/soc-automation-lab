#!/usr/bin/env bash
# make-env.sh - creates .env for the n8n stack (compose.yml + Caddyfile) - v2
#
# What it does:
#   - Writes .env next to this script (or to $ENV_FILE) with pinned image
#     versions, addressing and three random secrets: PostgreSQL password,
#     n8n encryption key and the task runner auth token.
#   - Never overwrites an existing .env: a new N8N_ENCRYPTION_KEY would make
#     every credential stored in n8n unreadable.
#   - Prints only variable names, never values.
#
# Usage (lab defaults shown; override any of them on another environment):
#   sudo N8N_HOST=n8n.lab N8N_IP=10.10.20.249 TZ=Europe/Warsaw ./make-env.sh
#
# After running: copy N8N_ENCRYPTION_KEY (best: the whole .env) to a password
# manager. Without it a database backup cannot be used.
#
# v2 (2026-10-27) - changes against v1:
#   - Fails (exit 1, no .env) if a secret cannot be generated. v1 used command
#     substitution inside a heredoc, which set -e does not catch: it reported
#     success and wrote empty secrets.
#   - .env is written to a temporary file and linked into place atomically,
#     so an interrupted run never leaves a half-written .env behind.
#   - Lab values are defaults that can be overridden from the environment,
#     the script no longer has to be edited.
#   - Exact image versions (not only the major version).
#   - Validates the result with "docker compose config -q" when possible.
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ENV_FILE=${ENV_FILE:-$SCRIPT_DIR/.env}

if [ -e "$ENV_FILE" ]; then
  echo "$ENV_FILE already exists - not touching it"
  exit 0
fi

command -v openssl >/dev/null || { echo "ERROR: openssl not found" >&2; exit 1; }

# Secrets go into variables first, so set -e stops the script if openssl fails
secret() { openssl rand -hex "$1" || { echo "ERROR: openssl rand failed" >&2; return 1; }; }
POSTGRES_PASSWORD=$(secret 24)
N8N_ENCRYPTION_KEY=$(secret 32)
N8N_RUNNERS_AUTH_TOKEN=$(secret 32)
for v in POSTGRES_PASSWORD N8N_ENCRYPTION_KEY N8N_RUNNERS_AUTH_TOKEN; do
  [[ ${!v} =~ ^[0-9a-f]{48,64}$ ]] || { echo "ERROR: $v was not generated" >&2; exit 1; }
done

umask 077
TMP_FILE=$(mktemp "$ENV_FILE.XXXXXX")
trap 'rm -f "$TMP_FILE"' EXIT

cat > "$TMP_FILE" <<EOF
# --- versions (pinned; n8n and runners must use the same N8N_VERSION) ---
N8N_VERSION=${N8N_VERSION:-2.44.6}
POSTGRES_VERSION=${POSTGRES_VERSION:-17.11}
REDIS_VERSION=${REDIS_VERSION:-7.4.11-alpine}
CADDY_VERSION=${CADDY_VERSION:-2.11.7-alpine}
# --- addressing ---
N8N_HOST=${N8N_HOST:-n8n.lab}
N8N_IP=${N8N_IP:-10.10.20.249}
TZ=${TZ:-Europe/Warsaw}
N8N_WORKER_CONCURRENCY=${N8N_WORKER_CONCURRENCY:-10}
# --- database ---
POSTGRES_DB=${POSTGRES_DB:-n8n}
POSTGRES_USER=${POSTGRES_USER:-n8n}
POSTGRES_PASSWORD=$POSTGRES_PASSWORD
# --- secrets (back up N8N_ENCRYPTION_KEY to a password manager) ---
N8N_ENCRYPTION_KEY=$N8N_ENCRYPTION_KEY
N8N_RUNNERS_AUTH_TOKEN=$N8N_RUNNERS_AUTH_TOKEN
EOF

# ln fails if .env appeared in the meantime - it is never overwritten
ln "$TMP_FILE" "$ENV_FILE" || { echo "ERROR: $ENV_FILE exists - not touching it" >&2; exit 1; }

echo "created $ENV_FILE (mode $(stat -c %a "$ENV_FILE")), variables:"
grep -vE '^(#|$)' "$ENV_FILE" | cut -d= -f1

if [ -f "$SCRIPT_DIR/compose.yml" ] && command -v docker >/dev/null; then
  # -q: validate without printing the config (it would contain the secrets)
  docker compose -f "$SCRIPT_DIR/compose.yml" --env-file "$ENV_FILE" config -q \
    && echo "docker compose config: OK"
fi
echo "Next: copy N8N_ENCRYPTION_KEY (or the whole .env) to a password manager."
