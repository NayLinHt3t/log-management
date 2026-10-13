import { join } from "node:path";
import { createPool, describeError, migrate, startHeartbeat, waitForDb } from "@logs/core";
import { buildApp } from "./app";
import { loadConfig } from "./config";
import { seed } from "./seed";

async function main() {
  const config = loadConfig();
  const pool = createPool(config.POSTGRES_URL, "logmgmt-backend", 20);
  await waitForDb(pool);
  // The backend owns the schema: ingest and worker wait for it to be healthy (docker-compose).
  await migrate(pool, join(__dirname, "..", "migrations"));
  if (config.SEED_DEMO) await seed(pool, config);

  const app = await buildApp({ pool, config });
  await app.listen({ port: config.PORT, host: config.HOST });
  const stopHeartbeat = startHeartbeat(pool, "backend", () => app.ctx.metrics.snapshot());

  let stopping = false;
  const shutdown = async (signal: string) => {
    if (stopping) return;
    stopping = true;
    app.log.info(`${signal} received, shutting down`);
    await app.close();
    await stopHeartbeat();
    await pool.end();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

main().catch((err) => {
  console.error(describeError(err));
  process.exit(1);
});
