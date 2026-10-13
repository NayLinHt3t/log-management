import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { TENANT_RE } from "@logs/core";
import {
  assertCanManage,
  generateApiKey,
  hashApiKey,
  hashPassword,
  requireAdmin,
  requireUser,
} from "../auth";
import { badRequest, forbidden, HttpError, notFound } from "../errors";

const TenantBody = z.object({
  id: z.string().regex(TENANT_RE, "1-32 characters: letters, digits, '_' or '-'"),
  name: z.string().trim().min(1).max(100),
  retention_days: z.coerce.number().int().min(7).max(3650).nullish(),
});

const UserBody = z.object({
  username: z.string().trim().regex(/^[A-Za-z0-9._@-]{3,64}$/, "3-64 characters: letters, digits, . _ @ -"),
  password: z.string().min(8, "at least 8 characters").max(200),
  role: z.enum(["admin", "viewer"]),
  tenant: z.string().regex(TENANT_RE).nullish(),
});

const KeyBody = z.object({
  name: z.string().trim().min(1).max(100),
  tenant: z.string().regex(TENANT_RE).nullish(),
});

const idParam = (p: unknown) => z.coerce.number().int().positive().parse((p as { id: unknown }).id);
const isUniqueViolation = (err: unknown) => (err as { code?: string }).code === "23505";
const isFkViolation = (err: unknown) => (err as { code?: string }).code === "23503";

export default async function adminRoutes(app: FastifyInstance) {
  const { pool, tenants, keys, config } = app.ctx;

  // ---- tenants ----------------------------------------------------------------------------
  app.get("/tenants", { preHandler: requireUser }, async (req) => {
    const own = req.user.tenant;
    const { rows } = await pool.query(
      `SELECT t.id, t.name, t.retention_days, t.created_at,
              COALESCE(t.retention_days, $1) AS effective_retention_days,
              (SELECT count(*)::int FROM event_partitions p WHERE p.tenant = t.id) AS partitions,
              (SELECT min(day) FROM event_partitions p WHERE p.tenant = t.id) AS oldest_day
         FROM tenants t ${own ? "WHERE t.id = $2" : ""} ORDER BY t.id`,
      own ? [config.RETENTION_DAYS, own] : [config.RETENTION_DAYS],
    );
    return { tenants: rows };
  });

  app.post("/tenants", { preHandler: requireAdmin }, async (req, reply) => {
    if (req.user.tenant !== null) throw forbidden("only a global admin can create tenants");
    const t = TenantBody.parse(req.body);
    try {
      await pool.query("INSERT INTO tenants (id, name, retention_days) VALUES ($1, $2, $3)", [
        t.id,
        t.name,
        t.retention_days ?? null,
      ]);
    } catch (err) {
      if (isUniqueViolation(err)) throw new HttpError(409, `tenant "${t.id}" already exists`);
      throw err;
    }
    // per-tenant tables are created up front so the first event does not pay for the DDL
    await pool.query("SELECT ensure_event_partition($1, (now() AT TIME ZONE 'UTC')::date)", [t.id]);
    tenants.invalidate();
    return reply.code(201).send({ ...t, retention_days: t.retention_days ?? null });
  });

  app.patch("/tenants/:id", { preHandler: requireAdmin }, async (req) => {
    if (req.user.tenant !== null) throw forbidden("only a global admin can change tenants");
    const id = z.string().regex(TENANT_RE).parse((req.params as { id: string }).id);
    const body = TenantBody.omit({ id: true }).partial().parse(req.body);
    const { rows } = await pool.query(
      `UPDATE tenants SET name = COALESCE($2, name),
              retention_days = CASE WHEN $3::boolean THEN $4::int ELSE retention_days END
        WHERE id = $1 RETURNING id, name, retention_days`,
      [id, body.name ?? null, body.retention_days !== undefined, body.retention_days ?? null],
    );
    if (!rows.length) throw notFound("tenant not found");
    return rows[0];
  });

  // ---- users ------------------------------------------------------------------------------
  app.get("/users", { preHandler: requireAdmin }, async (req) => {
    const own = req.user.tenant;
    const { rows } = await pool.query(
      `SELECT id, username, role, tenant, created_at, last_login_at FROM users
        ${own ? "WHERE tenant = $1" : ""} ORDER BY tenant NULLS FIRST, username`,
      own ? [own] : [],
    );
    return { users: rows };
  });

  app.post("/users", { preHandler: requireAdmin }, async (req, reply) => {
    const body = UserBody.parse(req.body);
    const tenant = body.tenant ?? (req.user.tenant as string | null) ?? null;
    if (body.role === "viewer" && !tenant) throw badRequest("a viewer must belong to a tenant");
    assertCanManage(req.user, tenant);
    try {
      const { rows } = await pool.query(
        `INSERT INTO users (username, password_hash, role, tenant) VALUES ($1, $2, $3, $4)
         RETURNING id, username, role, tenant, created_at`,
        [body.username, await hashPassword(body.password), body.role, tenant],
      );
      return reply.code(201).send(rows[0]);
    } catch (err) {
      if (isUniqueViolation(err)) throw new HttpError(409, `user "${body.username}" already exists`);
      if (isFkViolation(err)) throw badRequest(`tenant "${tenant}" does not exist`);
      throw err;
    }
  });

  app.delete("/users/:id", { preHandler: requireAdmin }, async (req, reply) => {
    const id = idParam(req.params);
    if (id === req.user.uid) throw badRequest("you cannot delete your own account");
    const { rows } = await pool.query("SELECT tenant FROM users WHERE id = $1", [id]);
    if (!rows.length) throw notFound("user not found");
    assertCanManage(req.user, rows[0].tenant);
    await pool.query("DELETE FROM users WHERE id = $1", [id]);
    return reply.code(204).send();
  });

  // ---- ingest API keys --------------------------------------------------------------------
  app.get("/api-keys", { preHandler: requireAdmin }, async (req) => {
    const own = req.user.tenant;
    const { rows } = await pool.query(
      `SELECT id, name, tenant, key_prefix, created_by, created_at, last_used_at, revoked_at
         FROM api_keys ${own ? "WHERE tenant = $1" : ""} ORDER BY id`,
      own ? [own] : [],
    );
    return { keys: rows };
  });

  app.post("/api-keys", { preHandler: requireAdmin }, async (req, reply) => {
    const body = KeyBody.parse(req.body);
    const tenant = body.tenant ?? (req.user.tenant as string | null) ?? null;
    assertCanManage(req.user, tenant);
    const key = generateApiKey();
    try {
      const { rows } = await pool.query(
        `INSERT INTO api_keys (name, tenant, key_hash, key_prefix, created_by)
         VALUES ($1, $2, $3, $4, $5) RETURNING id, name, tenant, key_prefix, created_at`,
        [body.name, tenant, hashApiKey(key), key.slice(0, 10), req.user.sub],
      );
      // the plain key is only ever returned here
      return reply.code(201).send({ ...rows[0], key });
    } catch (err) {
      if (isFkViolation(err)) throw badRequest(`tenant "${tenant}" does not exist`);
      throw err;
    }
  });

  app.delete("/api-keys/:id", { preHandler: requireAdmin }, async (req, reply) => {
    const id = idParam(req.params);
    const { rows } = await pool.query("SELECT tenant FROM api_keys WHERE id = $1", [id]);
    if (!rows.length) throw notFound("key not found");
    assertCanManage(req.user, rows[0].tenant);
    await pool.query("UPDATE api_keys SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL", [id]);
    keys.clear();
    return reply.code(204).send();
  });
}
