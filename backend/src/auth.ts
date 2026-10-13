import { createHash, randomBytes } from "node:crypto";
import argon2 from "argon2";
import type { FastifyReply, FastifyRequest } from "fastify";
import type { Pool } from "pg";
import { HttpError, forbidden, unauthorized } from "./errors";

/** JWT claims. `tenant` null = global admin. The tenant claim is what scopes every query. */
export interface AuthUser {
  uid: number;
  sub: string; // username
  role: "admin" | "viewer";
  tenant: string | null;
}

declare module "@fastify/jwt" {
  interface FastifyJWT {
    payload: AuthUser;
    user: AuthUser;
  }
}

export const hashPassword = (password: string) =>
  argon2.hash(password, { type: argon2.argon2id });

export const verifyPassword = (hash: string, password: string) =>
  argon2.verify(hash, password).catch(() => false);

// Verifying against a dummy hash for unknown users keeps response times similar,
// so the login endpoint does not reveal which usernames exist.
let dummyHash: Promise<string> | undefined;
export const getDummyHash = () => (dummyHash ??= hashPassword(randomBytes(16).toString("hex")));

/** preHandler: any logged-in user. */
export async function requireUser(req: FastifyRequest, _reply: FastifyReply) {
  try {
    await req.jwtVerify();
  } catch {
    throw unauthorized();
  }
}

/** preHandler: admin role (global or tenant admin). */
export async function requireAdmin(req: FastifyRequest, reply: FastifyReply) {
  await requireUser(req, reply);
  if (req.user.role !== "admin") throw forbidden("admin role required");
}

/**
 * Which tenant(s) may this request read?
 *  - users bound to a tenant always get their own tenant; asking for another one is a 403
 *  - global admins get the tenant they ask for (?tenant= or X-Tenant header), or "*" for all
 */
export function resolveScope(user: AuthUser, requested?: string | null): string {
  const want = requested?.trim() || undefined;
  if (user.tenant) {
    if (want && want !== "*" && want !== user.tenant) {
      throw forbidden(`you can only access tenant "${user.tenant}"`);
    }
    return user.tenant;
  }
  return want ?? "*";
}

export const requestedTenant = (req: FastifyRequest): string | undefined => {
  const q = (req.query as Record<string, unknown> | undefined)?.tenant;
  if (typeof q === "string" && q !== "") return q;
  const h = req.headers["x-tenant"];
  return typeof h === "string" && h !== "" ? h : undefined;
};

/** Write access: global admins can manage anything, tenant admins only their tenant. */
export function assertCanManage(user: AuthUser, tenant: string | null) {
  if (user.role !== "admin") throw forbidden("admin role required");
  if (user.tenant === null) return;
  if (tenant !== user.tenant) {
    throw forbidden(
      tenant === null
        ? "only a global admin can manage settings that apply to all tenants"
        : `you can only manage tenant "${user.tenant}"`,
    );
  }
}

// ---- ingest API keys -------------------------------------------------------------------

export const hashApiKey = (key: string) => createHash("sha256").update(key).digest("hex");
export const generateApiKey = () => "lm_" + randomBytes(24).toString("base64url");

interface KeyInfo {
  id: number;
  tenant: string | null;
  name: string;
}

/** Small cache so each ingest request does not hit the database for the key lookup. */
export class ApiKeyCache {
  private cache = new Map<string, { info: KeyInfo | null; at: number }>();
  private touched = new Map<number, number>();
  constructor(
    private pool: Pool,
    private ttlMs = 30_000,
  ) {}

  async lookup(key: string): Promise<KeyInfo | null> {
    const hash = hashApiKey(key);
    const hit = this.cache.get(hash);
    if (hit && Date.now() - hit.at < this.ttlMs) return hit.info;
    const { rows } = await this.pool.query(
      "SELECT id, tenant, name FROM api_keys WHERE key_hash = $1 AND revoked_at IS NULL",
      [hash],
    );
    const info: KeyInfo | null = rows[0] ?? null;
    this.cache.set(hash, { info, at: Date.now() });
    if (info) this.touch(info.id);
    return info;
  }

  private touch(id: number) {
    const last = this.touched.get(id) ?? 0;
    if (Date.now() - last < 60_000) return;
    this.touched.set(id, Date.now());
    void this.pool.query("UPDATE api_keys SET last_used_at = now() WHERE id = $1", [id]).catch(() => undefined);
  }

  clear() {
    this.cache.clear();
  }
}

export interface IngestPrincipal {
  kind: "api_key" | "user";
  name: string;
  /** null = may write to any tenant named in the payload */
  tenant: string | null;
}

/** Ingest accepts an API key (X-API-Key) or an admin's JWT (used by the UI upload). */
export async function authenticateIngest(
  req: FastifyRequest,
  keys: ApiKeyCache,
): Promise<IngestPrincipal> {
  const header = req.headers["x-api-key"];
  const key = Array.isArray(header) ? header[0] : header;
  if (key) {
    const info = await keys.lookup(key);
    if (!info) throw unauthorized("invalid or revoked API key");
    return { kind: "api_key", name: info.name, tenant: info.tenant };
  }
  if (req.headers.authorization) {
    try {
      await req.jwtVerify();
    } catch {
      throw unauthorized();
    }
    if (req.user.role !== "admin") throw forbidden("viewers cannot ingest data");
    return { kind: "user", name: req.user.sub, tenant: req.user.tenant };
  }
  throw unauthorized("send an X-API-Key header (or log in as an admin)");
}

// ---- brute-force protection for /auth/login --------------------------------------------

export class LoginLimiter {
  private attempts = new Map<string, { count: number; resetAt: number }>();
  constructor(
    private maxFailures = 10,
    private windowMs = 15 * 60_000,
  ) {}

  check(key: string) {
    const a = this.attempts.get(key);
    if (a && a.resetAt > Date.now() && a.count >= this.maxFailures) {
      const retry = Math.ceil((a.resetAt - Date.now()) / 1000);
      const err = new HttpError(429, `too many failed logins, try again in ${retry}s`);
      throw Object.assign(err, { retryAfter: retry });
    }
  }

  fail(key: string) {
    const now = Date.now();
    const a = this.attempts.get(key);
    if (!a || a.resetAt <= now) this.attempts.set(key, { count: 1, resetAt: now + this.windowMs });
    else a.count++;
    if (this.attempts.size > 10_000) {
      for (const [k, v] of this.attempts) if (v.resetAt <= now) this.attempts.delete(k);
    }
  }

  succeed(key: string) {
    this.attempts.delete(key);
  }
}
