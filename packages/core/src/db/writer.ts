import type { Pool } from "pg";
import type { NormalizedEvent } from "../schema";

const COLS = [
  "ts",
  "tenant",
  "source",
  "vendor",
  "product",
  "event_type",
  "event_subtype",
  "severity",
  "action",
  "outcome",
  "src_ip",
  "src_port",
  "dst_ip",
  "dst_port",
  "protocol",
  "username",
  "host",
  "process",
  "url",
  "http_method",
  "status_code",
  "rule_name",
  "rule_id",
  "cloud_account_id",
  "cloud_region",
  "cloud_service",
  "tags",
  "raw",
] as const;

const values = (e: NormalizedEvent): unknown[] => [
  e.ts,
  e.tenant,
  e.source,
  e.vendor,
  e.product,
  e.event_type,
  e.event_subtype,
  e.severity,
  e.action,
  e.outcome,
  e.src_ip,
  e.src_port,
  e.dst_ip,
  e.dst_port,
  e.protocol,
  e.username,
  e.host,
  e.process,
  e.url,
  e.http_method,
  e.status_code,
  e.rule_name,
  e.rule_id,
  e.cloud_account_id,
  e.cloud_region,
  e.cloud_service,
  e.tags,
  JSON.stringify(e.raw),
];

const placeholders = (rows: number) =>
  Array.from(
    { length: rows },
    (_, r) =>
      "(" +
      COLS.map(
        (c, i) => `$${r * COLS.length + i + 1}${c === "raw" ? "::jsonb" : ""}`,
      ).join(",") +
      ")",
  ).join(",");

const sqlState = (err: unknown) => (err as { code?: string })?.code ?? "";
/** Bad data (22), constraint (23), SQL (42) or raised (P0) errors are the event's fault -> reject it. */
const isDataError = (err: unknown) => /^(22|23|42|P0)/.test(sqlState(err));
const isMissingPartition = (err: unknown) =>
  sqlState(err) === "23514" && /no partition/i.test((err as Error).message);

export interface WriterStats {
  inserted: number;
  rejected: number;
  buffered: number;
  retries: number;
}

export class EventWriter {
  private buf: NormalizedEvent[] = [];
  private timer: NodeJS.Timeout;
  private flushing: Promise<void> | null = null;
  private partitions = new Set<string>(); // "tenant|YYYY-MM-DD" already ensured
  readonly stats: WriterStats = { inserted: 0, rejected: 0, buffered: 0, retries: 0 };

  constructor(
    private pool: Pool,
    private maxBatch = 200,
    flushMs = 1000,
    private onReject: (e: NormalizedEvent, err: unknown) => void = (e, err) =>
      console.error("rejected event", e.event_type, (err as Error).message),
    private maxBuffer = 50_000,
  ) {
    this.timer = setInterval(() => void this.flush(), flushMs);
    this.timer.unref();
  }

  /** Buffered path (syslog): returns immediately, flushed every 1s or 200 events. */
  add(e: NormalizedEvent) {
    if (this.buf.length >= this.maxBuffer) {
      this.stats.rejected++;
      this.onReject(e, new Error("ingest buffer full (database unavailable?)"));
      return;
    }
    this.buf.push(e);
    this.stats.buffered = this.buf.length;
    if (this.buf.length >= this.maxBatch) void this.flush();
  }

  /** Serialised flush; if the database is unreachable the batch goes back into the buffer. */
  flush(): Promise<void> {
    if (this.flushing) return this.flushing;
    if (!this.buf.length) return Promise.resolve();
    this.flushing = (async () => {
      try {
        while (this.buf.length) {
          const batch = this.buf.splice(0, Math.max(this.maxBatch, 500));
          try {
            await this.insertBatch(batch);
          } catch (err) {
            this.buf.unshift(...batch);
            this.stats.retries++;
            console.warn(`[writer] database unavailable, ${this.buf.length} events buffered: ${(err as Error).message}`);
            break;
          }
        }
      } finally {
        this.stats.buffered = this.buf.length;
        this.flushing = null;
      }
    })();
    return this.flushing;
  }

  /**
   * Direct path (HTTP): one multi-row INSERT; if it fails because of bad data, retry row by
   * row so one bad event can't lose the batch. Connection errors are thrown to the caller.
   */
  async insertBatch(
    events: NormalizedEvent[],
  ): Promise<{ inserted: number; rejected: number }> {
    let inserted = 0,
      rejected = 0;
    for (let i = 0; i < events.length; i += 500) {
      const chunk = events.slice(i, i + 500);
      try {
        await this.insertWithPartitions(chunk);
        inserted += chunk.length;
      } catch (err) {
        if (!isDataError(err)) throw err;
        for (const e of chunk) {
          try {
            await this.insertWithPartitions([e]);
            inserted++;
          } catch (rowErr) {
            if (!isDataError(rowErr)) throw rowErr;
            rejected++;
            this.onReject(e, rowErr);
          }
        }
      }
    }
    this.stats.inserted += inserted;
    this.stats.rejected += rejected;
    return { inserted, rejected };
  }

  private async insertWithPartitions(rows: NormalizedEvent[]) {
    await this.ensurePartitions(rows);
    try {
      await this.insert(rows);
    } catch (err) {
      if (!isMissingPartition(err)) throw err;
      // a partition was dropped by retention after we cached it: re-create and retry once
      this.partitions.clear();
      await this.ensurePartitions(rows);
      await this.insert(rows);
    }
  }

  /** Daily partitions per tenant are created on demand (the worker also pre-creates them). */
  private async ensurePartitions(rows: NormalizedEvent[]) {
    for (const e of rows) {
      const day = e.ts.toISOString().slice(0, 10);
      const key = `${e.tenant}|${day}`;
      if (this.partitions.has(key)) continue;
      await this.pool.query("SELECT ensure_event_partition($1, $2::date)", [e.tenant, day]);
      this.partitions.add(key);
    }
  }

  private insert(rows: NormalizedEvent[]) {
    return this.pool.query(
      `INSERT INTO events (${COLS.join(",")}) VALUES ${placeholders(rows.length)}`,
      rows.flatMap(values),
    );
  }

  async close() {
    clearInterval(this.timer);
    await this.flush();
  }
}
