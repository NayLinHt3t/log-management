import { z } from "zod";
import { databaseUrl } from "@logs/core";

const bool = z
  .union([z.boolean(), z.string()])
  .transform((v) => (typeof v === "boolean" ? v : /^(1|true|yes|on)$/i.test(v)));

// Convenience defaults so `npm run dev` works out of the box. Never used in production:
// there every secret must come from the environment (run.sh generates them into .env).
const DEV_DEFAULTS: Record<string, string> = {
  JWT_SECRET: "dev-only-jwt-secret-change-me-0123456789abcdef",
  ADMIN_PASSWORD: "Admin123!",
  VIEWER_PASSWORD: "Viewer123!",
  INGEST_API_KEY: "dev-ingest-key-change-me",
};

const Schema = z.object({
  NODE_ENV: z.string().default("development"),
  PORT: z.coerce.number().int().default(3000),
  HOST: z.string().default("0.0.0.0"),
  LOG_LEVEL: z.string().default("info"),
  POSTGRES_URL: z.string().min(1),
  JWT_SECRET: z.string().min(32, "must be at least 32 characters"),
  JWT_EXPIRES_IN: z.string().default("8h"),
  RETENTION_DAYS: z.coerce.number().int().min(7, "must be at least 7").default(7),
  LATE_EVENT_POLICY: z.enum(["restamp", "reject"]).default("restamp"),
  MAX_FUTURE_MINUTES: z.coerce.number().int().min(0).default(60),
  MAX_INGEST_MB: z.coerce.number().min(1).default(10),
  MAX_UPLOAD_MB: z.coerce.number().min(1).default(50),
  SEED_DEMO: bool.default(true),
  ADMIN_USERNAME: z.string().default("admin"),
  ADMIN_PASSWORD: z.string().min(8, "must be at least 8 characters"),
  VIEWER_PASSWORD: z.string().min(8, "must be at least 8 characters"),
  INGEST_API_KEY: z.string().min(16, "must be at least 16 characters").optional(),
  METRICS_TOKEN: z.string().min(16, "must be at least 16 characters").optional(),
  CORS_ORIGIN: z.string().optional(),
  PUBLIC_URL: z.string().optional(),
});

export type Config = z.infer<typeof Schema>;

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const isProd = (env.NODE_ENV ?? "development") === "production";
  const merged: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) if (v !== undefined && v !== "") merged[k] = v;
  merged.POSTGRES_URL = databaseUrl(env);
  if (!isProd) {
    for (const [k, v] of Object.entries(DEV_DEFAULTS)) merged[k] ??= v;
  }
  const parsed = Schema.safeParse(merged);
  if (!parsed.success) {
    const lines = parsed.error.issues.map((i) => ` - ${i.path.join(".")}: ${i.message}`);
    throw new Error(
      `Invalid configuration:\n${lines.join("\n")}\n(run ./run.sh up to generate .env, or see .env.example)`,
    );
  }
  if (isProd) {
    for (const key of ["JWT_SECRET", "ADMIN_PASSWORD", "VIEWER_PASSWORD", "INGEST_API_KEY"] as const) {
      if (/change-?me/i.test(String(parsed.data[key] ?? ""))) {
        throw new Error(`${key} still has a placeholder value; run ./run.sh up (it generates secrets) or edit .env`);
      }
    }
  }
  return parsed.data;
}
