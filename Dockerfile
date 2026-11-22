# Cloud Safeguard: one static binary with the console embedded.
# Build:  docker build -t cloud-safeguard .
# Run:    see deploy/docker/compose.yaml and docs/DEPLOY.md

FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build

FROM golang:1.24-alpine AS bin
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ cmd/
COPY internal/ internal/
COPY web/embed.go web/
COPY --from=web /src/web/dist web/dist
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/csg ./cmd/csg

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
 && addgroup -S -g 10001 csg && adduser -S -D -H -u 10001 -G csg csg \
 && mkdir -p /data && chown csg:csg /data && chmod 0700 /data
COPY --from=bin /out/csg /usr/local/bin/csg
COPY deploy/docker/entrypoint.sh /usr/local/bin/csg-entrypoint
USER csg
VOLUME ["/data"]
EXPOSE 8787
ENV CSG_DATA_DIR=/data CSG_ADDR=0.0.0.0:8787
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD wget -qO- http://127.0.0.1:8787/healthz >/dev/null || exit 1
ENTRYPOINT ["/usr/local/bin/csg-entrypoint"]
