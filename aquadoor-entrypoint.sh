#!/bin/sh
# AquaDoor config templating wrapper (#1780). Bifrost reads $APP_DIR/config.json but does NOT
# env-expand plain string fields (provider base_url, plugin config values). We render config.json
# from config.template.json at startup with a SCOPED envsubst var list, so:
#   - ${VAR} placeholders (non-secret deploy values: base_url, presidio URLs, OBO issuer/ids) are
#     substituted here;
#   - "$schema" and "env.VAR" SecretVar refs are left untouched (envsubst only touches the listed
#     vars) — bifrost expands "env.VAR" itself at runtime, so secrets (api keys, tokens) never land
#     in the rendered file.
# OBO's own secrets (Zitadel MachineKey actor JSON, upstream client secret) are read directly from
# env by the plugin and are never written to config.json at all.
set -e
: "${APP_DIR:=/app/data}"

# B1 (#1794): config_store + logs_store on the shared Postgres. SELF-CONFIGURING like the pii/obo
# plugins — the block is injected ONLY when BIFROST_PG_HOST is set; when it is empty the placeholder
# renders to nothing, so config.json is byte-identical to the proven SQLite default (no config_store/
# logs_store keys → embedded SQLite). This makes the SAME image safe whether or not the PG env is
# present, so a half-applied deploy (image before env) can never crashloop the gateway. The DB
# connection fields are bifrost-native `env.*` SecretVars (resolved at runtime), so the password is
# never rendered into config.json. retention_days caps log growth (the #1377 disk risk).
if [ -n "${BIFROST_PG_HOST:-}" ]; then
  _PG_CONN='{"host":"env.BIFROST_PG_HOST","port":"env.BIFROST_PG_PORT","user":"env.BIFROST_PG_USER","password":"env.BIFROST_PG_PASSWORD","db_name":"env.BIFROST_PG_DBNAME","ssl_mode":"env.BIFROST_PG_SSLMODE"}'
  BIFROST_STORE_BLOCK="\"config_store\":{\"enabled\":true,\"type\":\"postgres\",\"config\":${_PG_CONN}},\"logs_store\":{\"enabled\":true,\"type\":\"postgres\",\"retention_days\":14,\"config\":${_PG_CONN}},"
  echo "aquadoor-entrypoint: config_store + logs_store → shared Postgres (host=$BIFROST_PG_HOST db=${BIFROST_PG_DBNAME:-bifrost}, logs retention 14d)"
else
  BIFROST_STORE_BLOCK=""
  echo "aquadoor-entrypoint: BIFROST_PG_HOST unset → embedded SQLite config/logs store (default)"
fi
export BIFROST_STORE_BLOCK

if [ -f /app/config.template.json ]; then
  mkdir -p "$APP_DIR"
  # AQUADOOR_RUNNER_MCP_CLIENTS + AQUADOOR_OBO_RUNNER_CLIENTS are JSON arrays generated at deploy
  # time from the canonical MCP_MODULES list (the runner federates PER-MODULE at /mcp/<slug>), so
  # the module set stays single-sourced in the mono and the fork never drifts. They substitute
  # inline as valid JSON. ${BIFROST_STORE_BLOCK} is the whole config_store+logs_store block (or empty).
  envsubst '${AQUADOOR_LLM_BASE_URL} ${AQUADOOR_RUNNER_MCP_CLIENTS} ${AQUADOOR_OBO_RUNNER_CLIENTS} ${AQUADOOR_PRESIDIO_ANALYZER_URL} ${AQUADOOR_PRESIDIO_ANONYMIZER_URL} ${AQUADOOR_OBO_ISSUER} ${AQUADOOR_OBO_BACKEND_PROJECT_ID} ${AQUADOOR_OBO_UPSTREAM_CLIENT_ID} ${AQUADOOR_OBO_RUNNER_AUDIENCE} ${BIFROST_STORE_BLOCK}' \
    < /app/config.template.json > "$APP_DIR/config.json"
  echo "aquadoor-entrypoint: rendered $APP_DIR/config.json from template"
fi

exec /app/docker-entrypoint.sh "$@"
