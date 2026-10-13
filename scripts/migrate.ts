// Applies backend/migrations to the database in .env (the backend also does this on start).
import { join } from "node:path";
import { createPool, databaseUrl, describeError, migrate } from "@logs/core";

(async () => {
  const pool = createPool(databaseUrl(), "logmgmt-migrate");
  await migrate(pool, join(__dirname, "../backend/migrations"));
  await pool.end();
})().catch((err) => {
  const message = describeError(err);
  console.error(message);
  if (message.includes("ECONNREFUSED")) {
    console.error("No database is listening there. Start it with `npm run db:up` (or `./run.sh up`).");
  }
  process.exit(1);
});
