import { defineConfig } from "vitest/config";

export default defineConfig({
  // resolve @logs/core to its TypeScript source (same condition the dev scripts use)
  resolve: { conditions: ["logmgmt-source"] },
  ssr: { resolve: { conditions: ["logmgmt-source"], externalConditions: ["logmgmt-source"] } },
  test: {
    include: ["tests/**/*.test.ts"],
    environment: "node",
    // integration tests share one database
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 60_000,
  },
});
