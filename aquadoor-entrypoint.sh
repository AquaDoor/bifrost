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

if [ -f /app/config.template.json ]; then
  mkdir -p "$APP_DIR"
  envsubst '${AQUADOOR_LLM_BASE_URL} ${AQUADOOR_PRESIDIO_ANALYZER_URL} ${AQUADOOR_PRESIDIO_ANONYMIZER_URL} ${AQUADOOR_OBO_ISSUER} ${AQUADOOR_OBO_BACKEND_PROJECT_ID} ${AQUADOOR_OBO_UPSTREAM_CLIENT_ID}' \
    < /app/config.template.json > "$APP_DIR/config.json"
  echo "aquadoor-entrypoint: rendered $APP_DIR/config.json from template"
fi

exec /app/docker-entrypoint.sh "$@"
