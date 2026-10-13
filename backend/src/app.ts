import Fastify, { type FastifyInstance } from "fastify";
import fastifyJwt from "@fastify/jwt";
import multipart from "@fastify/multipart";
import cors from "@fastify/cors";
import type { Pool } from "pg";
import { EventWriter, QueryError } from "@logs/core";
import type { Config } from "./config";
import { ApiKeyCache, LoginLimiter } from "./auth";
import { HttpError } from "./errors";
import { Metrics } from "./metrics";
import { TenantCache } from "./tenants";
import authRoutes from "./routes/auth";
import ingestRoutes from "./routes/ingest";
import eventRoutes from "./routes/events";
import statsRoutes from "./routes/stats";
import alertRoutes from "./routes/alerts";
import adminRoutes from "./routes/admin";
import systemRoutes from "./routes/system";

export interface AppContext {
  pool: Pool;
  config: Config;
  tenants: TenantCache;
  keys: ApiKeyCache;
  writer: EventWriter;
  metrics: Metrics;
  loginLimiter: LoginLimiter;
}

declare module "fastify" {
  interface FastifyInstance {
    ctx: AppContext;
  }
}

export interface BuildOptions {
  pool: Pool;
  config: Config;
  logger?: boolean | { level: string };
}

export async function buildApp({ pool, config, logger }: BuildOptions): Promise<FastifyInstance> {
  const app = Fastify({
    logger: logger ?? { level: config.LOG_LEVEL },
    trustProxy: true, // behind Caddy: req.ip is the real client (used by the login limiter)
    bodyLimit: 1024 * 1024,
  });

  const ctx: AppContext = {
    pool,
    config,
    tenants: new TenantCache(pool),
    keys: new ApiKeyCache(pool),
    writer: new EventWriter(pool, 200, 1000, (e, err) =>
      app.log.warn({ tenant: e.tenant, source: e.source, err: (err as Error).message }, "event rejected by database"),
    ),
    metrics: new Metrics(),
    loginLimiter: new LoginLimiter(),
  };
  app.decorate("ctx", ctx);

  await app.register(fastifyJwt, {
    secret: config.JWT_SECRET,
    sign: { expiresIn: config.JWT_EXPIRES_IN },
  });
  await app.register(multipart, {
    limits: { fileSize: config.MAX_UPLOAD_MB * 1024 * 1024, files: 1, fields: 10 },
  });
  if (config.CORS_ORIGIN) {
    await app.register(cors, { origin: config.CORS_ORIGIN.split(",").map((s) => s.trim()) });
  }

  // NDJSON / JSON Lines and plain text (one syslog message per line) for POST /api/ingest
  app.addContentTypeParser(
    ["application/x-ndjson", "application/jsonl", "application/x-jsonlines", "text/plain"],
    { parseAs: "string", bodyLimit: config.MAX_INGEST_MB * 1024 * 1024 },
    (_req, body, done) => done(null, body),
  );

  app.setErrorHandler((err: any, req, reply) => {
    if (err instanceof HttpError || err instanceof QueryError) {
      if ((err as { retryAfter?: number }).retryAfter) reply.header("Retry-After", (err as any).retryAfter);
      return reply.code(err.statusCode).send({ error: err.message });
    }
    if (err?.name === "ZodError" && Array.isArray(err.issues)) {
      return reply.code(400).send({
        error: "invalid request",
        details: err.issues.map((i: any) => `${i.path.join(".") || "body"}: ${i.message}`),
      });
    }
    if (err?.validation) return reply.code(400).send({ error: err.message });
    if (typeof err?.statusCode === "number" && err.statusCode < 500) {
      return reply.code(err.statusCode).send({ error: err.message });
    }
    req.log.error({ err }, "unhandled error");
    return reply.code(500).send({ error: "internal server error" });
  });

  app.addHook("onResponse", async (req, reply) => {
    const route = req.routeOptions?.url ?? "unmatched";
    ctx.metrics.httpRequests.inc({ method: req.method, route, status: reply.statusCode });
    ctx.metrics.httpSeconds.inc({ route }, reply.elapsedTime / 1000);
  });

  app.addHook("onClose", async () => {
    await ctx.writer.close();
  });

  await app.register(
    async (api) => {
      await api.register(systemRoutes);
      await api.register(authRoutes);
      await api.register(ingestRoutes);
      await api.register(eventRoutes);
      await api.register(statsRoutes);
      await api.register(alertRoutes);
      await api.register(adminRoutes);
    },
    { prefix: "/api" },
  );

  return app;
}
