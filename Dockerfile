FROM node:22-alpine AS web
WORKDIR /src/web
COPY web/package.json web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY web/ ./
RUN npm run build
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev COMMIT=none DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/gw ./cmd/gw \
 && mkdir -p /out/data
FROM gcr.io/distroless/static-debian12:nonroot
LABEL org.opencontainers.image.title="mcp-gateway" \
      org.opencontainers.image.description="One login for all your AI tools' MCP servers" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/mcp-gateway/mcp-gateway"
COPY --from=build /out/gw /usr/local/bin/gw
COPY --from=build --chown=65532:65532 /out/data /data
ENV GW_LISTEN=0.0.0.0:8787 \
    GW_DATA_DIR=/data \
    GW_LOG_FORMAT=json
USER 65532:65532
VOLUME ["/data"]
EXPOSE 8787
HEALTHCHECK --interval=15s --timeout=5s --start-period=10s --retries=3 CMD ["/usr/local/bin/gw", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/gw"]
CMD ["serve"]
