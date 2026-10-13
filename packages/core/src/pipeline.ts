import { normalize } from "./normalizers";
import { parseSyslogLoose, type TimestampMode } from "./syslog/parser";
import type { NormalizedEvent } from "./schema";

export interface PipelineOptions {
  /** Tenants that exist; anything else is rejected. */
  knownTenants: ReadonlySet<string>;
  /** Tenant fixed by the credential (tenant-bound API key, inbox sub-folder, syslog mapping). */
  forcedTenant?: string;
  /** Used when neither the credential nor the record names a tenant. */
  defaultTenant?: string;
  sourceHint?: string;
  now?: Date;
  /** Events older than this are outside retention: re-stamped or rejected (see latePolicy). */
  maxAgeDays?: number;
  /** Allowed clock skew for timestamps in the future. */
  maxFutureMinutes?: number;
  latePolicy?: "restamp" | "reject";
  syslogTimestampMode?: TimestampMode;
}

export interface RecordError {
  index: number;
  error: string;
}

export interface PipelineResult {
  events: NormalizedEvent[];
  errors: RecordError[];
}

export const formatError = (err: unknown): string => {
  const issues = (err as { issues?: { path: PropertyKey[]; message: string }[] })?.issues;
  if (Array.isArray(issues) && issues.length) {
    return issues
      .map((i) => (i.path.length ? `${i.path.map(String).join(".")}: ${i.message}` : i.message))
      .join("; ");
  }
  return err instanceof Error ? err.message : String(err);
};

/**
 * The single path every source goes through: syslog lines, HTTP JSON, uploaded files and the
 * inbox folder all end up here, so tenant checks and timestamp rules are identical everywhere.
 */
export function processRecords(records: unknown[], opts: PipelineOptions): PipelineResult {
  const now = opts.now ?? new Date();
  const events: NormalizedEvent[] = [];
  const errors: RecordError[] = [];
  records.forEach((rec, index) => {
    try {
      events.push(processRecord(rec, opts, now));
    } catch (err) {
      errors.push({ index, error: formatError(err) });
    }
  });
  return { events, errors };
}

function processRecord(rec: unknown, opts: PipelineOptions, now: Date): NormalizedEvent {
  let record: any = rec;
  if (typeof rec === "string") {
    const tenant = opts.forcedTenant ?? opts.defaultTenant;
    if (!tenant) throw new Error("no tenant for this syslog line");
    record = parseSyslogLoose(rec, tenant, {
      now,
      timestampMode: opts.syslogTimestampMode ?? "auto",
    });
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("record must be a JSON object");
  }

  const claimed = typeof record.tenant === "string" ? record.tenant : undefined;
  if (opts.forcedTenant && claimed && claimed !== opts.forcedTenant) {
    throw new Error(
      `tenant "${claimed}" is not allowed for this credential (it is bound to "${opts.forcedTenant}")`,
    );
  }
  const tenant = opts.forcedTenant ?? claimed ?? opts.defaultTenant;
  if (!tenant) throw new Error("missing tenant");
  if (!opts.knownTenants.has(tenant)) throw new Error(`unknown tenant "${tenant}"`);

  const event = normalize(record, opts.sourceHint, { now, tenant });
  return applyTimePolicy(event, now, opts);
}

export function applyTimePolicy(
  event: NormalizedEvent,
  now: Date,
  opts: Pick<PipelineOptions, "maxAgeDays" | "maxFutureMinutes" | "latePolicy">,
): NormalizedEvent {
  const maxAgeDays = opts.maxAgeDays ?? 7;
  const maxFutureMinutes = opts.maxFutureMinutes ?? 60;
  const t = event.ts.getTime();
  const tooOld = t < now.getTime() - maxAgeDays * 86_400_000;
  const tooNew = t > now.getTime() + maxFutureMinutes * 60_000;
  if (!tooOld && !tooNew) return event;
  if (opts.latePolicy === "reject") {
    throw new Error(
      `timestamp ${event.ts.toISOString()} is outside the accepted window ` +
        `(${maxAgeDays} days back, ${maxFutureMinutes} minutes ahead)`,
    );
  }
  // Keep the event searchable: stamp it with the arrival time. The original timestamp
  // is still in `raw`, and the tag makes the adjustment visible.
  return { ...event, ts: now, tags: [...event.tags, "ts_restamped"] };
}
