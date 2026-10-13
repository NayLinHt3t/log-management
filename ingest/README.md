# ingest: syslog and file collector

Listens for syslog and watches the inbox folder. Every message goes through the shared
`processRecords()` pipeline in `@logs/core` (parse, normalize, validate, tenant + timestamp
policy) and then into a buffered batch writer (flushed every second or every 200 events,
retried if the database is unavailable).

**Syslog** on `SYSLOG_UDP_PORT` / `SYSLOG_TCP_PORT` (5514 in the container, published as 514):

* formats: RFC 3164, RFC 3164 with ISO timestamps (rsyslog), RFC 5424 (with structured
  data; what `logger -n` sends), CEF, and key=value payloads (demo firewall, Fortinet quoted
  values, iptables/UFW)
* TCP framing: newline-delimited and RFC 6587 octet counting, even mixed on one connection
  (`src/framing.ts`)
* lines that are not syslog at all are stored as `syslog_unparsed` instead of being dropped
* tenant: `SYSLOG_TENANT_MAP="10.20.0.0/16=demoB,192.168.1.10=demoA"` maps sender addresses;
  everything else goes to `SYSLOG_DEFAULT_TENANT`
* time: `SYSLOG_TIMESTAMP=auto` trusts timestamps that carry a year and zone (RFC 5424/ISO)
  and uses the arrival time for RFC 3164; `event` and `receive` force one or the other

**Inbox folder** (`INBOX_DIR`, `./data/inbox` mounted at `/data/inbox`): files copied into
`<inbox>/<tenant>/` are picked up every `INBOX_POLL_SECONDS` (5) once they have stopped
changing for 2 s. Accepted: JSON (array, object, CloudTrail `Records`), NDJSON, CSV with a
header, and `.log`/`.txt` syslog lines. The source is taken from the record, its shape, or the
file name (`aws_cloudtrail.json`, `m365_audit.json`, `ad_security_events.csv`). Afterwards the
file is moved to `processed/` or `failed/` with a `.result.json` report.

A small HTTP server on `HEALTH_PORT` (8081, inside the container only) returns the counters;
the same counters are written to `service_heartbeats` and shown in the UI.

```bash
npm run dev -w @logs/ingest        # listens on 5514; try: ../samples/send_syslog.sh localhost 5514
```
