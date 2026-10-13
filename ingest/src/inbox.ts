import { mkdir, readdir, readFile, rename, stat, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { parseFileContent, processRecords, TENANT_RE, type EventWriter } from "@logs/core";
import type { IngestConfig } from "./config";

const SKIP = new Set(["processed", "failed"]);
const MAX_BYTES = 100 * 1024 * 1024;

export interface InboxStats {
  files_processed: number;
  files_failed: number;
  file_events_accepted: number;
  file_events_rejected: number;
}

/**
 * "Point the system at files": anything copied into INBOX_DIR/<tenant>/ (JSON, NDJSON,
 * CloudTrail, CSV, .log) is parsed, normalised and stored, then moved to processed/ or
 * failed/ with a .result.json report next to it. Polling (not fs.watch) works on every
 * Docker volume type, including macOS bind mounts.
 */
export class InboxWatcher {
  readonly stats: InboxStats = {
    files_processed: 0,
    files_failed: 0,
    file_events_accepted: 0,
    file_events_rejected: 0,
  };
  private timer?: NodeJS.Timeout;
  private busy = false;

  constructor(
    private cfg: IngestConfig,
    private writer: EventWriter,
    private knownTenants: () => Promise<ReadonlySet<string>>,
    private log: (msg: string) => void = console.log,
  ) {}

  async start() {
    await mkdir(join(this.cfg.INBOX_DIR, "processed"), { recursive: true });
    await mkdir(join(this.cfg.INBOX_DIR, "failed"), { recursive: true });
    this.timer = setInterval(() => void this.scan(), this.cfg.INBOX_POLL_SECONDS * 1000);
    void this.scan();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
  }

  async scan() {
    if (this.busy) return;
    this.busy = true;
    try {
      const root = this.cfg.INBOX_DIR;
      for (const entry of await readdir(root, { withFileTypes: true })) {
        if (entry.name.startsWith(".") || SKIP.has(entry.name)) continue;
        if (entry.isDirectory()) {
          if (!TENANT_RE.test(entry.name)) continue;
          for (const f of await readdir(join(root, entry.name), { withFileTypes: true })) {
            if (f.isFile() && !f.name.startsWith(".")) await this.processFile(join(root, entry.name, f.name), f.name, entry.name);
          }
        } else if (entry.isFile()) {
          await this.processFile(join(root, entry.name), entry.name, undefined);
        }
      }
    } catch (err) {
      this.log(`[inbox] scan failed: ${(err as Error).message}`);
    } finally {
      this.busy = false;
    }
  }

  private async processFile(path: string, name: string, tenant: string | undefined) {
    const st = await stat(path);
    if (Date.now() - st.mtimeMs < 2000) return; // still being copied
    const stamp = new Date().toISOString().replace(/[-:]/g, "").replace(/\..*$/, "");
    const target = `${stamp}_${tenant ?? "root"}_${name}`;
    let report: Record<string, unknown>;
    let ok = false;
    try {
      if (st.size > MAX_BYTES) throw new Error(`file larger than ${MAX_BYTES / 1024 / 1024} MB`);
      const parsed = parseFileContent(await readFile(path, "utf8"), name);
      const result = processRecords(parsed.records, {
        knownTenants: await this.knownTenants(),
        forcedTenant: tenant, // a sub-folder pins the tenant, like a tenant-bound API key
        sourceHint: parsed.sourceHint,
        maxAgeDays: this.cfg.RETENTION_DAYS,
        maxFutureMinutes: this.cfg.MAX_FUTURE_MINUTES,
        latePolicy: this.cfg.LATE_EVENT_POLICY,
      });
      const stored = await this.writer.insertBatch(result.events);
      const rejected = result.errors.length + parsed.errors.length + stored.rejected;
      ok = stored.inserted > 0;
      report = {
        file: name,
        tenant: tenant ?? "(from records)",
        format: parsed.format,
        source_hint: parsed.sourceHint ?? null,
        accepted: stored.inserted,
        rejected,
        errors: [...parsed.errors.map((e) => `line ${e.line}: ${e.error}`), ...result.errors.map((e) => `record ${e.index}: ${e.error}`)].slice(0, 100),
      };
      this.stats.file_events_accepted += stored.inserted;
      this.stats.file_events_rejected += rejected;
    } catch (err) {
      report = { file: name, error: (err as Error).message };
    }
    const dir = join(this.cfg.INBOX_DIR, ok ? "processed" : "failed");
    await rename(path, join(dir, target));
    await writeFile(join(dir, `${target}.result.json`), JSON.stringify(report, null, 2));
    if (ok) this.stats.files_processed++;
    else this.stats.files_failed++;
    this.log(`[inbox] ${name} -> ${ok ? "processed" : "failed"} ${JSON.stringify({ accepted: report.accepted, rejected: report.rejected, error: report.error })}`);
  }
}
