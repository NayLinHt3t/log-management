import type { FastifyInstance, FastifyRequest } from "fastify";
import { z } from "zod";
import { parseFileContent, processRecords, type RecordError } from "@logs/core";
import { authenticateIngest, type IngestPrincipal } from "../auth";
import { badRequest, forbidden } from "../errors";

const MAX_RECORDS = 10_000;

const IngestQuery = z.object({
  tenant: z.string().optional(), // default tenant for records that do not name one
  source: z.string().optional(), // hint for records without a "source" field
});

/** JSON object, JSON array, NDJSON string or plain-text syslog lines -> records */
function bodyToRecords(req: FastifyRequest): { records: unknown[]; errors: RecordError[] } {
  const body = req.body;
  const type = String(req.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
  if (body === undefined || body === null || body === "") throw badRequest("empty body");
  if (typeof body === "string") {
    const lines = body.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
    if (type === "text/plain") return { records: lines, errors: [] };
    const records: unknown[] = [];
    const errors: RecordError[] = [];
    lines.forEach((l, i) => {
      try {
        records.push(JSON.parse(l));
      } catch {
        errors.push({ index: i, error: `line ${i + 1}: invalid JSON` });
      }
    });
    return { records, errors };
  }
  if (Array.isArray(body)) return { records: body, errors: [] };
  if (typeof body === "object") {
    const recs = (body as { events?: unknown; Records?: unknown }).events ?? (body as any).Records;
    if (Array.isArray(recs)) return { records: recs, errors: [] };
    return { records: [body], errors: [] };
  }
  throw badRequest("body must be a JSON object, an array, NDJSON or text lines");
}

declare module "fastify" {
  interface FastifyRequest {
    principal: IngestPrincipal | null;
  }
}

export default async function ingestRoutes(app: FastifyInstance) {
  const { config, tenants, keys, writer, metrics } = app.ctx;

  app.decorateRequest("principal", null);
  // Authenticate in onRequest, i.e. before a (possibly large) body is read and parsed.
  const onRequest = async (req: FastifyRequest) => {
    req.principal = await authenticateIngest(req, keys);
  };

  async function ingest(
    req: FastifyRequest,
    channel: "http" | "file",
    records: unknown[],
    preErrors: RecordError[],
    opts: { tenant?: string; source?: string },
  ) {
    const principal = req.principal!;
    if (records.length > MAX_RECORDS) throw badRequest(`at most ${MAX_RECORDS} records per request`);
    if (principal.tenant && opts.tenant && opts.tenant !== principal.tenant) {
      throw forbidden(`this credential can only write to tenant "${principal.tenant}"`);
    }
    const result = processRecords(records, {
      knownTenants: await tenants.get(),
      forcedTenant: principal.tenant ?? undefined,
      defaultTenant: opts.tenant,
      sourceHint: opts.source,
      maxAgeDays: config.RETENTION_DAYS,
      maxFutureMinutes: config.MAX_FUTURE_MINUTES,
      latePolicy: config.LATE_EVENT_POLICY,
    });
    const stored = await writer.insertBatch(result.events);
    const errors = [...preErrors, ...result.errors];
    const rejected = errors.length + stored.rejected;

    metrics.ingested.inc({ channel, result: "accepted" }, stored.inserted);
    if (rejected) metrics.ingested.inc({ channel, result: "rejected" }, rejected);
    req.log.info({ channel, principal: principal.name, accepted: stored.inserted, rejected }, "ingest");

    return {
      status: stored.inserted > 0 ? 200 : 400,
      body: {
        accepted: stored.inserted,
        rejected,
        restamped: result.events.filter((e) => e.tags.includes("ts_restamped")).length,
        errors: errors.slice(0, 50),
      },
    };
  }

  // POST /api/ingest  (JSON object | JSON array | {"events": [...]} | NDJSON | text/plain syslog lines)
  app.post(
    "/ingest",
    { bodyLimit: config.MAX_INGEST_MB * 1024 * 1024, onRequest },
    async (req, reply) => {
      const q = IngestQuery.parse(req.query);
      const { records, errors } = bodyToRecords(req);
      if (!records.length && !errors.length) throw badRequest("no records in body");
      const r = await ingest(req, "http", records, errors, q);
      return reply.code(r.status).send(r.body);
    },
  );

  // POST /api/ingest/file  multipart: file=<json|ndjson|csv|log>, optional fields tenant, source
  app.post("/ingest/file", { onRequest }, async (req, reply) => {
    if (!req.isMultipart()) throw badRequest("expected multipart/form-data with a 'file' field");
    let content: Buffer | undefined;
    let filename = "";
    const fields: Record<string, string> = {};
    for await (const part of req.parts()) {
      if (part.type === "file") {
        content = await part.toBuffer();
        filename = part.filename;
      } else if (typeof part.value === "string") {
        fields[part.fieldname] = part.value;
      }
    }
    if (!content) throw badRequest("no file uploaded (use the form field name 'file')");
    const q = IngestQuery.parse(req.query);
    const parsed = parseFileContent(content.toString("utf8"), filename);
    const preErrors = parsed.errors.map((e) => ({ index: -1, error: `line ${e.line}: ${e.error}` }));
    if (!parsed.records.length && !preErrors.length) throw badRequest("the file contains no records");
    const r = await ingest(req, "file", parsed.records, preErrors, {
      tenant: fields.tenant || q.tenant,
      source: fields.source || q.source || parsed.sourceHint,
    });
    return reply.code(r.status).send({ file: filename, format: parsed.format, ...r.body });
  });
}
