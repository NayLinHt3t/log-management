import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { buildEventWhere, withTenantScope } from "@logs/core";
import { requestedTenant, requireUser, resolveScope } from "../auth";
import { badRequest } from "../errors";
import { EVENT_COLUMNS, FilterQuery, serializeEvent, timeRange } from "./common";

const SearchQuery = FilterQuery.extend({
  limit: z.coerce.number().int().min(1).max(500).default(100),
  cursor: z.string().max(200).optional(),
});

const COUNT_CAP = 10_000;

// cursor = base64url("<ts ISO>|<id>") of the last row: stable keyset pagination
const encodeCursor = (ts: Date, id: string) =>
  Buffer.from(`${ts.toISOString()}|${id}`).toString("base64url");

function decodeCursor(c: string) {
  const [ts, id] = Buffer.from(c, "base64url").toString().split("|");
  if (!ts || !/^\d+$/.test(id ?? "") || isNaN(new Date(ts).getTime())) throw badRequest("invalid cursor");
  return { ts, id };
}

const toCsv = (rows: ReturnType<typeof serializeEvent>[]) => {
  const cols = ["@timestamp", "tenant", "source", "event_type", "severity", "action", "outcome", "user", "src_ip", "src_port", "dst_ip", "dst_port", "host", "process", "rule_name"] as const;
  const esc = (v: unknown) => {
    const s = v === undefined || v === null ? "" : String(v);
    return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
  };
  return [cols.join(","), ...rows.map((r) => cols.map((c) => esc((r as any)[c])).join(","))].join("\n");
};

export default async function eventRoutes(app: FastifyInstance) {
  const { pool } = app.ctx;

  app.get("/events", { preHandler: requireUser }, async (req, reply) => {
    const q = SearchQuery.parse(req.query);
    const scope = resolveScope(req.user, requestedTenant(req));
    const { from, to } = timeRange(q.from, q.to);
    const started = Date.now();
    const { where, params } = buildEventWhere({
      tenant: scope === "*" ? undefined : scope,
      from,
      to,
      sources: q.source,
      q: q.q,
    });

    let keyset = "";
    const pageParams = [...params];
    if (q.cursor) {
      const c = decodeCursor(q.cursor);
      pageParams.push(c.ts, c.id);
      keyset = ` AND (ts, id) < ($${pageParams.length - 1}::timestamptz, $${pageParams.length}::bigint)`;
    }
    pageParams.push(q.limit + 1);

    const { rows, total } = await withTenantScope(pool, scope, async (db) => {
      const page = await db.query(
        `SELECT ${EVENT_COLUMNS} FROM events WHERE ${where}${keyset}
         ORDER BY ts DESC, id DESC LIMIT $${pageParams.length}`,
        pageParams,
      );
      const count = q.cursor
        ? null
        : await db.query(
            `SELECT count(*)::int AS n FROM (SELECT 1 FROM events WHERE ${where} LIMIT ${COUNT_CAP + 1}) s`,
            params,
          );
      return { rows: page.rows, total: count ? count.rows[0].n : null };
    });

    const hasMore = rows.length > q.limit;
    const events = rows.slice(0, q.limit).map(serializeEvent);
    const last = rows[q.limit - 1];
    const body = {
      events,
      next_cursor: hasMore && last ? encodeCursor(new Date(last.ts), String(last.id)) : null,
      total: total === null ? null : Math.min(total, COUNT_CAP),
      total_capped: total !== null && total > COUNT_CAP,
      took_ms: Date.now() - started,
      scope,
      from: from.toISOString(),
      to: to.toISOString(),
    };
    return reply.send(body);
  });

  // CSV export of the current search (first 5000 rows)
  app.get("/events/export.csv", { preHandler: requireUser }, async (req, reply) => {
    const q = SearchQuery.parse(req.query);
    const scope = resolveScope(req.user, requestedTenant(req));
    const { from, to } = timeRange(q.from, q.to);
    const { where, params } = buildEventWhere({
      tenant: scope === "*" ? undefined : scope,
      from,
      to,
      sources: q.source,
      q: q.q,
    });
    const rows = await withTenantScope(pool, scope, async (db) =>
      (await db.query(`SELECT ${EVENT_COLUMNS} FROM events WHERE ${where} ORDER BY ts DESC, id DESC LIMIT 5000`, params)).rows,
    );
    return reply
      .header("Content-Type", "text/csv; charset=utf-8")
      .header("Content-Disposition", `attachment; filename="events-${from.toISOString().slice(0, 10)}.csv"`)
      .send(toCsv(rows.map(serializeEvent)));
  });
}
