set -euo pipefail
cd "$(dirname "$0")/.."
go build -o bin/gw ./cmd/gw
ENVF=$(mktemp)
ADMIN=$(bin/gw keygen admin)
cat > "$ENVF" <<ENV
GW_PUBLIC_URL=http://localhost:8787
GW_INTERNAL_TOKEN=$(bin/gw keygen internal)
GW_MASTER_KEY=$(bin/gw keygen master)
GW_BOOTSTRAP_ADMIN_KEY=$ADMIN
GW_IMAGE=mcp-gateway:local
ENV
COMPOSE="docker compose -f deploy/compose.split.yml --env-file $ENVF -p mcp-gateway-split-test"
cleanup() { $COMPOSE down -v >/dev/null 2>&1 || true; rm -f "$ENVF"; }
trap cleanup EXIT INT TERM PIPE HUP
$COMPOSE up -d --wait
$COMPOSE ps
cd test/blackbox
GW_BLACKBOX_URL=http://localhost:8787 GW_BLACKBOX_ADMIN_KEY=$ADMIN GW_BLACKBOX_FIXTURE_HOST=host.docker.internal \
  go test -count=1 -v .
