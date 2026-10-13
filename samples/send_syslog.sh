#!/usr/bin/env bash
# Send the sample firewall and router syslog lines to the appliance.
#
#   ./samples/send_syslog.sh [host] [port] [udp|tcp|both]
#   ./samples/send_syslog.sh localhost 514 both
#
# Uses nc (netcat). Also shows the equivalent `logger` command (util-linux, Linux only).
set -euo pipefail
HOST=${1:-localhost}
PORT=${2:-514}
MODE=${3:-both}
DIR=$(cd "$(dirname "$0")" && pwd)
# UDP has no handshake: if "localhost" resolved to ::1 first (macOS does this) and nothing
# listened there, the datagrams would vanish without an error. Use the IPv4 loopback.
if [ "$HOST" = localhost ]; then HOST=127.0.0.1; fi

command -v nc >/dev/null 2>&1 || { echo "nc (netcat) is required: apt install netcat-openbsd / brew install netcat" >&2; exit 1; }

send_udp() { # one datagram per line
  while IFS= read -r line; do
    [ -n "$line" ] && printf '%s' "$line" | nc -u -w1 "$HOST" "$PORT" || true
  done <"$1"
}
send_tcp() { # newline-framed messages over one connection
  nc -w2 "$HOST" "$PORT" <"$1" || true
}

if [ "$MODE" = udp ] || [ "$MODE" = both ]; then
  send_udp "$DIR/firewall.log"
  echo "sent $(grep -c . "$DIR/firewall.log") firewall lines over UDP to $HOST:$PORT"
fi
if [ "$MODE" = tcp ] || [ "$MODE" = both ]; then
  send_tcp "$DIR/network.log"
  echo "sent $(grep -c . "$DIR/network.log") router lines over TCP to $HOST:$PORT"
fi

if command -v logger >/dev/null 2>&1 && logger --help 2>&1 | grep -q -- '--server'; then
  logger -n "$HOST" -P "$PORT" -d -t demo-app "test message from logger (RFC 5424 over UDP)" && echo "sent 1 RFC 5424 message with logger"
else
  echo "tip (Linux): logger -n $HOST -P $PORT -d -t demo-app \"hello\"   # RFC 5424 over UDP"
fi
echo "Search for them in the UI: source:firewall or source:network (they appear within a few seconds)."
