import { BlockList, isIP } from "node:net";
import { databaseUrl, type TimestampMode } from "@logs/core";

const int = (v: string | undefined, d: number) => (v && /^\d+$/.test(v) ? Number(v) : d);

export function loadConfig(env = process.env) {
  const ts = (env.SYSLOG_TIMESTAMP ?? "auto") as TimestampMode;
  if (!["auto", "event", "receive"].includes(ts)) throw new Error("SYSLOG_TIMESTAMP must be auto, event or receive");
  return {
    POSTGRES_URL: databaseUrl(env),
    SYSLOG_HOST: env.SYSLOG_HOST ?? "0.0.0.0",
    SYSLOG_UDP_PORT: int(env.SYSLOG_UDP_PORT, 5514),
    SYSLOG_TCP_PORT: int(env.SYSLOG_TCP_PORT, 5514),
    SYSLOG_DEFAULT_TENANT: env.SYSLOG_DEFAULT_TENANT ?? "demoA",
    SYSLOG_TENANT_MAP: env.SYSLOG_TENANT_MAP ?? "",
    SYSLOG_TIMESTAMP: ts,
    INBOX_DIR: env.INBOX_DIR ?? "./data/inbox",
    INBOX_POLL_SECONDS: int(env.INBOX_POLL_SECONDS, 5),
    RETENTION_DAYS: Math.max(7, int(env.RETENTION_DAYS, 7)),
    MAX_FUTURE_MINUTES: int(env.MAX_FUTURE_MINUTES, 60),
    LATE_EVENT_POLICY: (env.LATE_EVENT_POLICY === "reject" ? "reject" : "restamp") as "reject" | "restamp",
    HEALTH_PORT: int(env.HEALTH_PORT, 8081),
  };
}
export type IngestConfig = ReturnType<typeof loadConfig>;

/**
 * Syslog has no tenant field, so the tenant comes from the sender's address:
 *   SYSLOG_TENANT_MAP="10.20.0.0/16=demoB,192.168.1.10=demoA"
 * Unmapped senders go to SYSLOG_DEFAULT_TENANT.
 */
export class TenantResolver {
  private rules: { list: BlockList; tenant: string }[] = [];

  constructor(
    map: string,
    private fallback: string,
  ) {
    for (const entry of map.split(",").map((s) => s.trim()).filter(Boolean)) {
      const [cidr, tenant] = entry.split("=").map((s) => s.trim());
      if (!cidr || !tenant) throw new Error(`bad SYSLOG_TENANT_MAP entry "${entry}" (expected cidr=tenant)`);
      const [addr, bits] = cidr.split("/");
      const family = isIP(addr);
      if (!family) throw new Error(`bad address in SYSLOG_TENANT_MAP: "${cidr}"`);
      const type = family === 6 ? "ipv6" : "ipv4";
      const list = new BlockList();
      if (bits === undefined) list.addAddress(addr, type);
      else list.addSubnet(addr, Number(bits), type);
      this.rules.push({ list, tenant });
    }
  }

  resolve(remote: string): string {
    const addr = remote.startsWith("::ffff:") ? remote.slice(7) : remote;
    const type = isIP(addr) === 6 ? "ipv6" : "ipv4";
    for (const r of this.rules) {
      try {
        if (r.list.check(addr, type)) return r.tenant;
      } catch {
        /* family mismatch */
      }
    }
    return this.fallback;
  }
}
