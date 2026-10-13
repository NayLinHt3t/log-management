import type { Pool } from "pg";

/** The set of existing tenant ids, refreshed every 30 s (ingest rejects unknown tenants). */
export class TenantCache {
  private ids = new Set<string>();
  private loadedAt = 0;
  constructor(
    private pool: Pool,
    private ttlMs = 30_000,
  ) {}

  async get(): Promise<ReadonlySet<string>> {
    if (Date.now() - this.loadedAt > this.ttlMs) await this.refresh();
    return this.ids;
  }

  async refresh() {
    const { rows } = await this.pool.query("SELECT id FROM tenants");
    this.ids = new Set(rows.map((r) => r.id as string));
    this.loadedAt = Date.now();
  }

  invalidate() {
    this.loadedAt = 0;
  }
}
