import { describe, it, expect } from "vitest";
import { EventSchema } from "../../packages/core/src/schema";

describe("EventSchema", () => {
  it("accepts a minimal valid event", () => {
    const e = EventSchema.parse({
      ts: "2025-08-20T07:20:00Z",
      tenant: "demoA",
      source: "api",
      event_type: "app_login_failed",
    });
    expect(e.severity).toBe(0);
    expect(e.tags).toEqual([]);
  });

  it("rejects an unknown source and a bad IP", () => {
    expect(
      EventSchema.safeParse({
        ts: "2025-08-20T07:20:00Z",
        tenant: "t",
        source: "nope",
        event_type: "x",
      }).success,
    ).toBe(false);
    expect(
      EventSchema.safeParse({
        ts: "2025-08-20T07:20:00Z",
        tenant: "t",
        source: "api",
        event_type: "x",
        src_ip: "999.1.1.1",
      }).success,
    ).toBe(false);
  });
});
