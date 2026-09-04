# AquaDoor fork Dockerfile (#1780) — builds the bifrost-http binary from LOCAL module sources via a
# go workspace, so the fork-local core/mcp bijection AND the in-tree aquadoor-* plugins are compiled
# in. The upstream transports/Dockerfile uses GOWORK=off + pinned proxy versions, which would EXCLUDE
# every fork-local change — do not use it for the fork. This is the deploy target (deploy.yml
# `bifrost` job: context=fork, dockerfile=fork/Dockerfile). Based on transports/Dockerfile.local, but
# the go workspace AUTO-DISCOVERS ./plugins/* so new plugins (aquadoor-pii, aquadoor-obo, …) need no
# edit here.

# --- UI Build Stage: Build the React + Vite frontend ---
  FROM node:25-alpine3.23@sha256:bdf2cca6fe3dabd014ea60163eca3f0f7015fbd5c7ee1b0e9ccb4ced6eb02ef4 AS ui-builder
  WORKDIR /app
  RUN apk upgrade --no-cache
  COPY ui/package*.json ./
  RUN npm ci
  COPY ui/ ./
  RUN npm run build-enterprise

  # --- Go Build Stage: Compile the Go binary using local modules ---
  FROM golang:1.27.0-alpine3.24@sha256:4c9fe60190a2a3350ddc51de80d0224b8a6698d12bdfc999fee45ea9d6c46dbc AS builder
  WORKDIR /build
  RUN apk upgrade --no-cache && \
    apk add --no-cache gcc musl-dev sqlite-dev binutils binutils-gold
  ENV CGO_ENABLED=1 GOOS=linux

  # Copy all local modules (context is the fork root)
  COPY core/ ./core/
  COPY framework/ ./framework/
  COPY plugins/ ./plugins/
  COPY transports/ ./transports/
  COPY cli/ ./cli/

  # Set up a go workspace so local module sources (fork-modified core + in-tree plugins) win over the
  # pinned proxy versions in transports/go.mod. Plugins are auto-discovered so additions need no edit.
  RUN go work init ./core ./framework ./transports ./cli && \
    for d in ./plugins/*/; do go work use "$d"; done

  # Copy UI build output into transports (embedded via //go:embed all:ui in main.go)
  COPY --from=ui-builder /app/out ./transports/bifrost-http/ui

  # Build the binary with CGO enabled and static SQLite linking
  ARG VERSION=unknown
  RUN cd /build/transports && \
    go build \
      -ldflags="-w -s -X main.Version=v${VERSION} -extldflags '-static'" \
      -a -trimpath \
      -tags "sqlite_static" \
      -o /app/main \
      ./bifrost-http
  RUN test -f /app/main || (echo "Build failed" && exit 1)

  # --- Runtime Stage: Minimal runtime image ---
  FROM alpine:3.23.5@sha256:fd791d74b68913cbb027c6546007b3f0d3bc45125f797758156952bc2d6daf40
  WORKDIR /app
  # gettext provides envsubst for the config templating wrapper (aquadoor-entrypoint.sh)
  RUN apk upgrade --no-cache && \
    apk add --no-cache musl libgcc ca-certificates zlib gettext

  COPY --from=builder /app/main .
  COPY --from=builder /build/transports/docker-entrypoint.sh .
  # AquaDoor config template + wrapper entrypoint (renders config.json from env at start)
  COPY config.template.json /app/config.template.json
  COPY aquadoor-entrypoint.sh /app/aquadoor-entrypoint.sh

  ARG ARG_APP_PORT=8080
  ARG ARG_APP_HOST=0.0.0.0
  ARG ARG_LOG_LEVEL=info
  ARG ARG_LOG_STYLE=json
  ARG ARG_APP_DIR=/app/data
  ENV APP_PORT=$ARG_APP_PORT \
    APP_HOST=$ARG_APP_HOST \
    LOG_LEVEL=$ARG_LOG_LEVEL \
    LOG_STYLE=$ARG_LOG_STYLE \
    APP_DIR=$ARG_APP_DIR

  RUN mkdir -p "$APP_DIR/logs" && \
    adduser -D -s /bin/sh appuser && \
    chown -R appuser:appuser /app && \
    chown -R appuser:0 "$APP_DIR" && \
    { [ "$APP_DIR" = "/app" ] || chmod -R g=rwX "$APP_DIR"; } && \
    chmod +x /app/docker-entrypoint.sh /app/aquadoor-entrypoint.sh
  USER 1000:0

  VOLUME ["${APP_DIR}"]
  EXPOSE $APP_PORT

  HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:${APP_PORT}/health || exit 1

  ENTRYPOINT ["/app/aquadoor-entrypoint.sh"]
  CMD ["/app/main"]
