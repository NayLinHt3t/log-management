#!/usr/bin/env bash
# Log Management: one-command operations (Linux/macOS; needs Docker with Compose v2).
#
#   ./run.sh up        create .env with random secrets (first run), build, start, wait, print logins
#   ./run.sh saas      same, with docker-compose.saas.yml (set DOMAIN + TLS_MODE=acme in .env first)
#   ./run.sh status    container and pipeline health
#   ./run.sh logs [svc] follow logs (backend, ingest, worker, web, db)
#   ./run.sh demo      send every sample (syslog, HTTP, files) and a brute-force burst
#   ./run.sh down      stop everything (data is kept)
#   ./run.sh reset     stop and DELETE all stored data (database + certificates)
#   ./run.sh info      print URL, logins and the ingest key again
set -euo pipefail
cd "$(dirname "$0")"

COMPOSE=(docker compose)
if [ "${LOGMGMT_MODE:-}" = saas ] || { [ -f .env ] && grep -q '^LOGMGMT_MODE=saas' .env; }; then
  COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.saas.yml)
fi

bold() { printf '\033[1m%s\033[0m\n' "$*"; }
die() { echo "error: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required ($2)"; }
rand() { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c "${1:-32}" || true; }

env_get() { [ -f .env ] && grep -E "^$1=" .env | tail -n1 | cut -d= -f2- || true; }
# a hand-edited .env often lacks the final newline; appending to it would glue two lines together
env_newline() {
  if [ -s .env ] && [ -n "$(tail -c1 .env)" ]; then echo >>.env; fi
}
env_set() { # replace or append KEY=VALUE without sed -i (portable across GNU/BSD)
  local tmp
  env_newline
  tmp=$(mktemp)
  if grep -qE "^$1=" .env; then
    awk -v k="$1" -v v="$2" 'index($0, k"=")==1 {print k"="v; next} {print}' .env >"$tmp"
  else
    cat .env >"$tmp"
    printf '%s=%s\n' "$1" "$2" >>"$tmp"
  fi
  cat "$tmp" >.env && rm -f "$tmp"
}

host_ip() {
  local ip=""
  if command -v hostname >/dev/null && hostname -I >/dev/null 2>&1; then ip=$(hostname -I | awk '{print $1}'); fi
  if [ -z "$ip" ] && command -v ipconfig >/dev/null; then ip=$(ipconfig getifaddr en0 2>/dev/null || true); fi
  echo "${ip:-localhost}"
}

ensure_env() {
  local key val line added=""
  if [ ! -f .env ]; then
    cp .env.example .env
    echo "created .env from .env.example"
  else
    # an existing (older or hand-written) .env: add every setting it does not have yet,
    # with the default from .env.example; values already in .env are never changed here
    env_newline
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in '' | '#'*) continue ;; esac
      key=${line%%=*}
      if ! grep -qE "^${key}=" .env; then
        printf '%s\n' "$line" >>.env
        added="$added $key"
      fi
    done <.env.example
    if [ -n "$added" ]; then echo "added missing settings to .env:$added"; fi
  fi
  # every secret that is missing or still a placeholder gets a random value
  for key in POSTGRES_PASSWORD JWT_SECRET ADMIN_PASSWORD VIEWER_PASSWORD INGEST_API_KEY; do
    val=$(env_get "$key")
    if [ -z "$val" ] || [[ "$val" == *change-me* ]]; then
      case "$key" in
        JWT_SECRET) env_set "$key" "$(rand 48)" ;;
        INGEST_API_KEY) env_set "$key" "lm_$(rand 32)" ;;
        *) env_set "$key" "$(rand 16)" ;;
      esac
      echo "generated $key"
    fi
  done
  if [ -z "$(env_get PUBLIC_URL)" ]; then
    local domain
    domain=$(env_get DOMAIN)
    env_set PUBLIC_URL "https://${domain:-localhost}"
  fi
  mkdir -p data/inbox/demoA data/inbox/demoB
  chmod -R a+rwX data 2>/dev/null || true # the ingest container runs as an unprivileged user
}

# host name that the edge serves: the domain in Let's Encrypt mode, otherwise localhost
edge_host() {
  if [ -n "$(env_get DOMAIN)" ] && [ "$(env_get TLS_MODE)" = acme ]; then env_get DOMAIN; else echo localhost; fi
}
edge_url() {
  local port
  port=$(env_get HTTPS_PORT)
  echo "https://$(edge_host):${port:-443}"
}

wait_healthy() {
  local id status i
  printf 'waiting for the API'
  for i in $(seq 1 90); do
    id=$("${COMPOSE[@]}" ps -q backend 2>/dev/null || true)
    status=""
    [ -n "$id" ] && status=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$id" 2>/dev/null || true)
    if [ "$status" = healthy ]; then
      echo " ready"
      break
    fi
    printf '.'
    sleep 2
  done
  if [ "$status" != healthy ]; then
    echo
    "${COMPOSE[@]}" ps
    die "the API did not become healthy in 3 minutes; check ./run.sh logs backend"
  fi
  # then the HTTPS edge (resolving the edge host to this machine, so DNS is not needed yet)
  local host port
  host=$(edge_host)
  port=$(env_get HTTPS_PORT)
  port=${port:-443}
  for i in $(seq 1 30); do
    if curl -ksf --resolve "$host:$port:127.0.0.1" "https://$host:$port/api/health" >/dev/null 2>&1; then
      echo "HTTPS is answering on https://$host:$port"
      return 0
    fi
    sleep 2
  done
  echo "warning: HTTPS is not answering yet on https://$host:$port (with a domain: check DNS and ./run.sh logs web)"
}

info() {
  local port domain url
  port=$(env_get HTTPS_PORT)
  domain=$(env_get DOMAIN)
  url="https://${domain:-$(host_ip)}"
  [ -n "$port" ] && [ "$port" != 443 ] && url="$url:$port"
  echo
  bold "Log Management is running"
  echo "  UI / API     $url   (also https://localhost; self-signed certificate unless TLS_MODE=acme)"
  echo "  Admin        $(env_get ADMIN_USERNAME):$(env_get ADMIN_PASSWORD)"
  echo "  Viewers      viewerA (tenant demoA), viewerB (tenant demoB), password: $(env_get VIEWER_PASSWORD)"
  echo "  Ingest key   $(env_get INGEST_API_KEY)   (header X-API-Key)"
  echo "  Syslog       udp/tcp $(host_ip):$(env_get SYSLOG_PORT | sed 's/^$/514/')"
  echo "  Inbox        ./data/inbox/<tenant>/   (JSON, NDJSON, CloudTrail, CSV, .log)"
  echo
  echo "  Try it:      ./run.sh demo"
}

# Containers outside this project that already publish a port we need (for example the
# database of an older copy of this project on 5433) would make `up` fail halfway through.
check_ports() {
  local ports p line name project published found=""
  ports="$(env_get HTTP_PORT | sed 's/^$/80/') $(env_get HTTPS_PORT | sed 's/^$/443/') $(env_get SYSLOG_PORT | sed 's/^$/514/')"
  case " ${COMPOSE[*]} " in
    *saas*) ;; # the SaaS override publishes no database port
    *) ports="$ports $(env_get DB_PORT | sed 's/^$/5433/')" ;;
  esac
  while IFS='|' read -r name project published; do
    [ -n "$name" ] && [ "$project" != logmgmt ] || continue
    for p in $ports; do
      case "$published" in
        *":$p->"*) found="$found  $name (project: ${project:-none}) uses port $p"$'\n' ;;
      esac
    done
  done < <(docker ps --format '{{.Names}}|{{.Label "com.docker.compose.project"}}|{{.Ports}}')
  if [ -n "$found" ]; then
    echo "error: these running containers already use ports that this project needs:" >&2
    printf '%s' "$found" >&2
    echo "Stop them (docker stop <name>), or pick other ports in .env (HTTP_PORT, HTTPS_PORT, SYSLOG_PORT, DB_PORT)." >&2
    exit 1
  fi
}

cmd_up() {
  need docker "https://docs.docker.com/engine/install/"
  docker info >/dev/null 2>&1 || die "Docker is installed but not running: start Docker Desktop (or: sudo systemctl start docker)"
  "${COMPOSE[@]}" version >/dev/null 2>&1 || die "Docker Compose v2 is required (docker compose ...)"
  need curl "used to wait for the API"
  ensure_env
  check_ports
  "${COMPOSE[@]}" up -d --build
  wait_healthy
  info
}

cmd_demo() {
  need python3 "used by the sample sender scripts"
  local base
  base=$(edge_url)
  bold "1/4 syslog (UDP + TCP)"
  ./samples/send_syslog.sh localhost "$(env_get SYSLOG_PORT | sed 's/^$/514/')"
  bold "2/4 HTTP POST /api/ingest (the assignment's sample JSON)"
  python3 samples/post_logs.py --url "$base" --insecure
  bold "3/4 files into the inbox folder"
  cp samples/aws_cloudtrail.json data/inbox/demoB/ && cp samples/m365_audit.json data/inbox/demoB/
  cp samples/ad_security_events.csv data/inbox/demoA/ && cp samples/crowdstrike_detections.json data/inbox/demoA/
  echo "copied 4 files; they are processed within 5 seconds (see data/inbox/processed/)"
  bold "4/4 brute-force burst (fires the default alert rule)"
  python3 samples/simulate.py --url "$base" --insecure --scenario bruteforce
  echo
  echo "Open $base and look at the dashboard, Search, and Alerts."
}

case "${1:-help}" in
  up) cmd_up ;;
  saas)
    ensure_env
    env_set LOGMGMT_MODE saas
    COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.saas.yml)
    [ -n "$(env_get DOMAIN)" ] || echo "note: DOMAIN is empty, so the VM's IP is served with a self-signed certificate"
    cmd_up
    ;;
  down) "${COMPOSE[@]}" down ;;
  reset)
    read -r -p "Delete ALL stored events, users and alerts? [y/N] " yes
    [ "$yes" = y ] || [ "$yes" = Y ] || exit 1
    "${COMPOSE[@]}" down -v
    ;;
  logs) shift; "${COMPOSE[@]}" logs -f --tail=100 "$@" ;;
  status)
    "${COMPOSE[@]}" ps
    port=$(env_get HTTPS_PORT)
    curl -ks --resolve "$(edge_host):${port:-443}:127.0.0.1" "$(edge_url)/api/health" && echo
    ;;
  demo) cmd_demo ;;
  info) info ;;
  *)
    sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
    ;;
esac
