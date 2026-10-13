import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { buildEventWhere, evaluateRule, GROUP_BY, TENANT_RE, withTenantScope } from "@logs/core";
import { assertCanManage, requestedTenant, requireAdmin, requireUser, resolveScope } from "../auth";
import { badRequest, notFound } from "../errors";

const RuleBody = z.object({
  name: z.string().trim().min(1).max(120),
  description: z.string().trim().max(500).nullish(),
  tenant: z.string().regex(TENANT_RE).nullish(), // null/absent = all tenants (global admins only)
  enabled: z.boolean().default(true),
  query: z.string().trim().max(1000).default(""),
  group_by: z.enum(GROUP_BY).nullish(),
  threshold: z.coerce.number().int().min(1).max(100000).default(1),
  window_minutes: z.coerce.number().int().min(1).max(1440).default(5),
  severity: z.coerce.number().int().min(0).max(10).default(5),
  webhook_url: z
    .string()
    .trim()
    .url()
    .refine((u) => /^https?:\/\//.test(u), "must be http(s)")
    .nullish()
    .or(z.literal("").transform(() => null)),
});
type RuleInput = z.infer<typeof RuleBody>;

const ListQuery = z.object({
  status: z.enum(["open", "acknowledged", "closed", "all"]).default("all"),
  tenant: z.string().optional(),
  limit: z.coerce.number().int().min(1).max(500).default(100),
});

const RULE_COLUMNS = `id, tenant, name, description, enabled, query, group_by, threshold, window_minutes,
  severity, webhook_url, created_by, created_at, updated_at`;

/** Compile the rule's query once so syntax errors are reported when the rule is saved. */
function validateQuery(q: string) {
  buildEventWhere({ q });
}

export default async function alertRoutes(app: FastifyInstance) {
  const { pool } = app.ctx;

  // ---- alerts -----------------------------------------------------------------------------
  app.get("/alerts", { preHandler: requireUser }, async (req) => {
    const q = ListQuery.parse(req.query);
    const scope = resolveScope(req.user, requestedTenant(req));
    return withTenantScope(pool, scope, async (db) => {
      const params: unknown[] = [];
      const conds: string[] = [];
      if (scope !== "*") conds.push(`tenant = $${params.push(scope)}`);
      if (q.status !== "all") conds.push(`status = $${params.push(q.status)}`);
      const where = conds.length ? `WHERE ${conds.join(" AND ")}` : "";
      const { rows } = await db.query(
        `SELECT id, rule_id, rule_name, tenant, group_by, group_key, severity, status, event_count,
                first_seen, last_seen, message, query, sample, notify_status, notified_at,
                acknowledged_by, acknowledged_at, created_at, updated_at
           FROM alerts ${where} ORDER BY created_at DESC, id DESC LIMIT ${q.limit}`,
        params,
      );
      const counts = await db.query(
        `SELECT status, count(*)::int AS n FROM alerts ${scope === "*" ? "" : "WHERE tenant = $1"} GROUP BY 1`,
        scope === "*" ? [] : [scope],
      );
      const byStatus: Record<string, number> = { open: 0, acknowledged: 0, closed: 0 };
      for (const r of counts.rows) byStatus[r.status] = r.n;
      return { alerts: rows.map((r) => ({ ...r, id: String(r.id) })), counts: byStatus };
    });
  });

  const setStatus = (status: "acknowledged" | "closed") =>
    async (req: any) => {
      const id = z.coerce.number().int().positive().parse(req.params.id);
      const { rows } = await pool.query("SELECT tenant FROM alerts WHERE id = $1", [id]);
      if (!rows.length) throw notFound("alert not found");
      assertCanManage(req.user, rows[0].tenant);
      const updated = await pool.query(
        `UPDATE alerts SET status = $2, updated_at = now(),
                acknowledged_by = COALESCE(acknowledged_by, $3),
                acknowledged_at = COALESCE(acknowledged_at, now())
          WHERE id = $1 RETURNING id, status, acknowledged_by, acknowledged_at`,
        [id, status, req.user.sub],
      );
      return { ...updated.rows[0], id: String(updated.rows[0].id) };
    };
  app.post("/alerts/:id/ack", { preHandler: requireAdmin }, setStatus("acknowledged"));
  app.post("/alerts/:id/close", { preHandler: requireAdmin }, setStatus("closed"));

  // ---- rules ------------------------------------------------------------------------------
  app.get("/alert-rules", { preHandler: requireUser }, async (req) => {
    const scope = resolveScope(req.user, requestedTenant(req));
    return withTenantScope(pool, scope, async (db) => {
      const { rows } = await db.query(
        `SELECT ${RULE_COLUMNS},
                (SELECT count(*)::int FROM alerts a WHERE a.rule_id = r.id AND a.status = 'open'
                   ${scope === "*" ? "" : "AND a.tenant = $1"}) AS open_alerts
           FROM alert_rules r ORDER BY id`,
        scope === "*" ? [] : [scope],
      );
      return { rules: rows };
    });
  });

  const normalizeRule = (req: any, body: RuleInput) => {
    // tenant admins can only create rules for their own tenant
    const tenant = body.tenant ?? (req.user.tenant as string | null) ?? null;
    assertCanManage(req.user, tenant);
    validateQuery(body.query);
    return { ...body, tenant, group_by: body.group_by ?? null, webhook_url: body.webhook_url ?? null };
  };

  app.post("/alert-rules", { preHandler: requireAdmin }, async (req, reply) => {
    const r = normalizeRule(req, RuleBody.parse(req.body));
    const { rows } = await pool.query(
      `INSERT INTO alert_rules (tenant, name, description, enabled, query, group_by, threshold,
                                window_minutes, severity, webhook_url, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING ${RULE_COLUMNS}`,
      [r.tenant, r.name, r.description ?? null, r.enabled, r.query, r.group_by, r.threshold,
       r.window_minutes, r.severity, r.webhook_url, req.user.sub],
    );
    return reply.code(201).send(rows[0]);
  });

  app.put("/alert-rules/:id", { preHandler: requireAdmin }, async (req) => {
    const id = z.coerce.number().int().positive().parse((req.params as any).id);
    const existing = await pool.query("SELECT tenant FROM alert_rules WHERE id = $1", [id]);
    if (!existing.rowCount) throw notFound("rule not found");
    assertCanManage(req.user, existing.rows[0].tenant);
    const r = normalizeRule(req, RuleBody.parse(req.body));
    const { rows } = await pool.query(
      `UPDATE alert_rules SET tenant=$2, name=$3, description=$4, enabled=$5, query=$6, group_by=$7,
              threshold=$8, window_minutes=$9, severity=$10, webhook_url=$11, updated_at=now()
        WHERE id = $1 RETURNING ${RULE_COLUMNS}`,
      [id, r.tenant, r.name, r.description ?? null, r.enabled, r.query, r.group_by, r.threshold,
       r.window_minutes, r.severity, r.webhook_url],
    );
    return rows[0];
  });

  app.patch("/alert-rules/:id", { preHandler: requireAdmin }, async (req) => {
    const id = z.coerce.number().int().positive().parse((req.params as any).id);
    const { enabled } = z.object({ enabled: z.boolean() }).parse(req.body);
    const existing = await pool.query("SELECT tenant FROM alert_rules WHERE id = $1", [id]);
    if (!existing.rowCount) throw notFound("rule not found");
    assertCanManage(req.user, existing.rows[0].tenant);
    const { rows } = await pool.query(
      `UPDATE alert_rules SET enabled = $2, updated_at = now() WHERE id = $1 RETURNING ${RULE_COLUMNS}`,
      [id, enabled],
    );
    return rows[0];
  });

  app.delete("/alert-rules/:id", { preHandler: requireAdmin }, async (req, reply) => {
    const id = z.coerce.number().int().positive().parse((req.params as any).id);
    const existing = await pool.query("SELECT tenant FROM alert_rules WHERE id = $1", [id]);
    if (!existing.rowCount) throw notFound("rule not found");
    assertCanManage(req.user, existing.rows[0].tenant);
    await pool.query("DELETE FROM alert_rules WHERE id = $1", [id]);
    return reply.code(204).send();
  });

  // Dry run: what would this rule match right now? (used by the "Test rule" button)
  app.post("/alert-rules/test", { preHandler: requireUser }, async (req) => {
    const body = RuleBody.partial({ name: true }).parse(req.body);
    const scope = resolveScope(req.user, body.tenant ?? requestedTenant(req));
    validateQuery(body.query ?? "");
    const ruleTenant = scope === "*" ? (body.tenant ?? null) : scope;
    if (body.tenant && ruleTenant !== body.tenant) throw badRequest("tenant mismatch");
    const hits = await withTenantScope(pool, scope, (db) =>
      evaluateRule(db, {
        tenant: ruleTenant,
        query: body.query ?? "",
        group_by: body.group_by ?? null,
        threshold: body.threshold ?? 1,
        window_minutes: body.window_minutes ?? 5,
      }),
    );
    return { would_fire: hits.length > 0, hits };
  });
}
