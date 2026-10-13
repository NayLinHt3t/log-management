import { describe, it, expect } from "vitest";
import { processRecords } from "../../packages/core/src/pipeline";

const NOW = new Date("2026-10-12T12:00:00Z");
const known = new Set(["demoA", "demoB"]);

describe("ingest pipeline", () => {
  it("rejects unknown tenants and keeps going with the rest of the batch", () => {
    const r = processRecords(
      [
        { tenant: "demoA", source: "api", event_type: "ok" },
        { tenant: "evil", source: "api", event_type: "nope" },
      ],
      { knownTenants: known, now: NOW },
    );
    expect(r.events).toHaveLength(1);
    expect(r.errors).toEqual([{ index: 1, error: 'unknown tenant "evil"' }]);
  });

  it("a tenant-bound credential cannot write into another tenant", () => {
    const r = processRecords(
      [
        { source: "api", event_type: "no tenant field" },
        { tenant: "demoB", source: "api", event_type: "cross-tenant attempt" },
      ],
      { knownTenants: known, forcedTenant: "demoA", now: NOW },
    );
    expect(r.events.map((e) => e.tenant)).toEqual(["demoA"]);
    expect(r.errors[0].error).toMatch(/not allowed/);
  });

  it("re-stamps events older than retention so they stay searchable", () => {
    const r = processRecords(
      [
        { tenant: "demoA", source: "api", event_type: "old", "@timestamp": "2025-08-20T07:20:00Z" },
        { tenant: "demoA", source: "api", event_type: "recent", "@timestamp": "2026-10-10T07:20:00Z" },
      ],
      { knownTenants: known, now: NOW, maxAgeDays: 7 },
    );
    expect(r.events[0].ts).toEqual(NOW);
    expect(r.events[0].tags).toContain("ts_restamped");
    expect(r.events[0].raw["@timestamp"]).toBe("2025-08-20T07:20:00Z"); // original kept in raw
    expect(r.events[1].ts.toISOString()).toBe("2026-10-10T07:20:00.000Z");
  });

  it("can reject out-of-window events instead", () => {
    const r = processRecords(
      [{ tenant: "demoA", source: "api", event_type: "future", "@timestamp": "2027-01-01T00:00:00Z" }],
      { knownTenants: known, now: NOW, latePolicy: "reject" },
    );
    expect(r.events).toHaveLength(0);
    expect(r.errors[0].error).toMatch(/outside the accepted window/);
  });

  it("turns raw syslog lines into events for the default tenant", () => {
    const r = processRecords(
      ["<134>Aug 20 12:44:56 fw01 action=deny src=10.0.1.10 dst=8.8.8.8 dpt=53 proto=udp"],
      { knownTenants: known, defaultTenant: "demoB", now: NOW },
    );
    expect(r.events[0]).toMatchObject({ tenant: "demoB", source: "firewall", action: "deny" });
    expect(r.events[0].ts).toEqual(NOW); // RFC 3164 has no year/zone -> arrival time
  });

  it("reports schema problems with the field name", () => {
    const r = processRecords(
      [{ tenant: "demoA", source: "api", event_type: "x", ip: "999.1.1.1" }],
      { knownTenants: known, now: NOW },
    );
    expect(r.errors[0].error).toMatch(/^src_ip: Invalid IP address/);
  });
});
