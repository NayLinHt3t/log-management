// Local development: backend, ingest, worker (hot reload via tsx) and the Vite UI in one terminal.
//   npm run db:up    # Postgres in Docker on localhost:5433
//   npm run dev      # then open http://localhost:5173
// Services read .env (loaded by `tsx --env-file-if-exists=.env`) and import @logs/core from
// source through the "logmgmt-source" export condition, so no build step is needed.
import { spawn, type ChildProcess } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

// Stop early, with the fix, when node_modules is older than the package.json files (for example
// after pulling changes). Otherwise the first sign is a "Failed to resolve import" error in Vite.
const root = join(__dirname, "..");
const missing = new Set<string>();
for (const dir of [".", "packages/core", "backend", "ingest", "worker", "frontend"]) {
  const pkg = JSON.parse(readFileSync(join(root, dir, "package.json"), "utf8"));
  for (const name of Object.keys({ ...pkg.dependencies, ...pkg.devDependencies })) {
    const places = [join(root, dir, "node_modules", name), join(root, "node_modules", name)];
    if (!places.some((p) => existsSync(join(p, "package.json")))) missing.add(name);
  }
}
if (missing.size > 0) {
  console.error(`Not installed: ${[...missing].join(", ")}`);
  console.error("Install the dependencies first with `npm ci` (or `npm install`), then run `npm run dev` again.");
  process.exit(1);
}

const services: { name: string; color: number; cmd: string[]; env?: Record<string, string> }[] = [
  { name: "backend", color: 36, cmd: ["npx", "tsx", "watch", "--conditions=logmgmt-source", "backend/src/index.ts"] },
  {
    name: "ingest",
    color: 35,
    cmd: ["npx", "tsx", "watch", "--conditions=logmgmt-source", "ingest/src/index.ts"],
    // unprivileged ports in development; the appliance publishes 514 -> 5514
    env: { SYSLOG_UDP_PORT: "5514", SYSLOG_TCP_PORT: "5514", INBOX_DIR: "./data/inbox", HEALTH_PORT: "8081" },
  },
  { name: "worker", color: 33, cmd: ["npx", "tsx", "watch", "--conditions=logmgmt-source", "worker/src/index.ts"] },
  { name: "ui", color: 32, cmd: ["npm", "run", "dev", "-w", "frontend"] },
];

const children: ChildProcess[] = [];
for (const s of services) {
  const child = spawn(s.cmd[0], s.cmd.slice(1), {
    env: { ...process.env, NODE_ENV: "development", ...s.env },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const prefix = `\x1b[${s.color}m${s.name.padEnd(7)}\x1b[0m │ `;
  const pipe = (stream: NodeJS.ReadableStream | null) =>
    stream?.on("data", (buf: Buffer) => {
      for (const line of buf.toString().split(/\r?\n/)) if (line.trim()) process.stdout.write(prefix + line + "\n");
    });
  pipe(child.stdout);
  pipe(child.stderr);
  child.on("exit", (code) => process.stdout.write(`${prefix}exited with code ${code}\n`));
  children.push(child);
}

const stop = () => {
  for (const c of children) c.kill("SIGTERM");
  setTimeout(() => process.exit(0), 1500);
};
process.on("SIGINT", stop);
process.on("SIGTERM", stop);
