# @logs/core

Shared by backend, ingest and worker, so every path applies the same rules.

| Module | Purpose |
|---|---|
| `schema.ts` | the common event schema (zod) and enums (sources, actions, outcomes, tenant id format) |
| `syslog/parser.ts`, `syslog/cef.ts`, `syslog/kv.ts` | RFC 3164 / RFC 5424 / CEF / key=value parsing, field aliases across vendors |
| `normalizers/*` | one normalizer per source (firewall, network, api, crowdstrike, aws, m365, ad); source auto-detection |
| `pipeline.ts` | `processRecords()`: records → validated events, tenant enforcement, timestamp policy |
| `files.ts` | file parsing: JSON, CloudTrail `Records`, NDJSON, CSV, syslog lines; source from file name |
| `query.ts` | the search language compiled to parameterized SQL |
| `alerts.ts` | rule evaluation (`evaluateRule`) and alert deduplication (`recordHits`) |
| `db/*` | pool, migrations runner, batched writer with on-demand partitions, `withTenantScope()` (RLS), heartbeats |

During development the package is imported from source through the `logmgmt-source` export
condition (`tsx --conditions=logmgmt-source`, see `vitest.config.ts`); the containers use the
compiled `dist/`.
