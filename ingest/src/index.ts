import dgram from "node:dgram";
import http from "node:http";
import net from "node:net";
import {
  createPool,
  describeError,
  EventWriter,
  processRecords,
  splitLines,
  startHeartbeat,
  waitForDb,
} from "@logs/core";
import { loadConfig, TenantResolver } from "./config";
import { SyslogFramer } from "./framing";
import { InboxWatcher } from "./inbox";

const cfg = loadConfig();
const log = (msg: string) => console.log(`${new Date().toISOString()} ${msg}`);

const stats = {
  syslog_udp_messages: 0,
  syslog_tcp_messages: 0,
  syslog_tcp_connections: 0,
  events_accepted: 0,
  events_rejected: 0,
  events_buffered: 0,
  last_event_at: null as string | null,
  by_source: {} as Record<string, number>,
};

async function main() {
  const pool = createPool(cfg.POSTGRES_URL, "logmgmt-ingest");
  await waitForDb(pool);

  // known tenants, refreshed every 30 s (unknown tenants are rejected)
  let tenants: ReadonlySet<string> = new Set();
  let tenantsAt = 0;
  const knownTenants = async () => {
    if (Date.now() - tenantsAt > 30_000) {
      try {
        tenants = new Set((await pool.query("SELECT id FROM tenants")).rows.map((r) => r.id));
        tenantsAt = Date.now();
      } catch (err) {
        log(`[ingest] could not refresh tenants: ${(err as Error).message}`);
      }
    }
    return tenants;
  };
  await knownTenants();

  const writer = new EventWriter(pool, 200, 1000, (e, err) => {
    stats.events_rejected++;
    log(`[ingest] rejected ${e.source}/${e.event_type}: ${(err as Error).message}`);
  });
  const resolver = new TenantResolver(cfg.SYSLOG_TENANT_MAP, cfg.SYSLOG_DEFAULT_TENANT);

  /** Syslog lines from one datagram / TCP read -> normalised events into the buffered writer. */
  const handleLines = async (lines: string[], remote: string) => {
    if (!lines.length) return;
    const result = processRecords(lines, {
      knownTenants: await knownTenants(),
      forcedTenant: resolver.resolve(remote),
      syslogTimestampMode: cfg.SYSLOG_TIMESTAMP,
      maxAgeDays: cfg.RETENTION_DAYS,
      maxFutureMinutes: cfg.MAX_FUTURE_MINUTES,
      latePolicy: cfg.LATE_EVENT_POLICY,
    });
    for (const e of result.events) {
      writer.add(e);
      stats.events_accepted++;
      stats.by_source[e.source] = (stats.by_source[e.source] ?? 0) + 1;
    }
    if (result.events.length) stats.last_event_at = new Date().toISOString();
    for (const err of result.errors) {
      stats.events_rejected++;
      log(`[syslog] from ${remote} rejected: ${err.error}`);
    }
  };

  // ---- UDP 514 (container port 5514) ----------------------------------------------------
  // IPv4 by default: Docker disables IPv6 inside containers unless the network enables it.
  const udp = dgram.createSocket(net.isIPv6(cfg.SYSLOG_HOST) ? "udp6" : "udp4");
  udp.on("message", (msg, rinfo) => {
    stats.syslog_udp_messages++;
    void handleLines(splitLines(msg.toString("utf8")), rinfo.address);
  });
  udp.on("error", (err) => log(`[syslog/udp] ${err.message}`));
  await new Promise<void>((resolve) =>
    udp.bind(cfg.SYSLOG_UDP_PORT, cfg.SYSLOG_HOST, resolve),
  );
  log(`[syslog] UDP listening on ${cfg.SYSLOG_UDP_PORT}`);

  // ---- TCP 514 (newline or octet-counted framing) -----------------------------------------
  const tcp = net.createServer((sock) => {
    stats.syslog_tcp_connections++;
    const framer = new SyslogFramer();
    const remote = sock.remoteAddress ?? "unknown";
    sock.setTimeout(10 * 60_000, () => sock.destroy());
    sock.on("data", (chunk: Buffer) => {
      const lines = framer.push(chunk);
      stats.syslog_tcp_messages += lines.length;
      void handleLines(lines, remote);
    });
    sock.on("end", () => {
      const lines = framer.end();
      stats.syslog_tcp_messages += lines.length;
      void handleLines(lines, remote);
    });
    sock.on("error", () => sock.destroy());
  });
  await new Promise<void>((resolve) => tcp.listen(cfg.SYSLOG_TCP_PORT, cfg.SYSLOG_HOST, resolve));
  log(`[syslog] TCP listening on ${cfg.SYSLOG_TCP_PORT}`);

  // ---- inbox folder ---------------------------------------------------------------------
  const inbox = new InboxWatcher(cfg, writer, knownTenants, log);
  await inbox.start();
  log(`[inbox] watching ${cfg.INBOX_DIR} every ${cfg.INBOX_POLL_SECONDS}s`);

  // ---- health + heartbeat -----------------------------------------------------------------
  const snapshot = () => ({
    ...stats,
    events_buffered: writer.stats.buffered,
    db_inserted: writer.stats.inserted,
    db_retries: writer.stats.retries,
    ...inbox.stats,
    default_tenant: cfg.SYSLOG_DEFAULT_TENANT,
  });
  const health = http.createServer((_req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ status: "ok", ...snapshot() }));
  });
  health.listen(cfg.HEALTH_PORT);
  const stopHeartbeat = startHeartbeat(pool, "ingest", snapshot);

  const shutdown = async (signal: string) => {
    log(`[ingest] ${signal}, flushing and shutting down`);
    inbox.stop();
    udp.close();
    tcp.close();
    health.close();
    await writer.close();
    await stopHeartbeat();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error(describeError(err));
  process.exit(1);
});
