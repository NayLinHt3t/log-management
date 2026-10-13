import { describe, expect, it } from "vitest";
import { describeError } from "@logs/core";

describe("describeError", () => {
  it("lists every attempt of an AggregateError (localhost = ::1 + 127.0.0.1 on macOS)", () => {
    const attempts = [
      Object.assign(new Error("connect ECONNREFUSED ::1:5433"), { code: "ECONNREFUSED" }),
      Object.assign(new Error("connect ECONNREFUSED 127.0.0.1:5433"), { code: "ECONNREFUSED" }),
    ];
    const err = Object.assign(new AggregateError(attempts), { code: "ECONNREFUSED" });
    expect(err.message).toBe("");
    expect(describeError(err)).toBe("connect ECONNREFUSED ::1:5433; connect ECONNREFUSED 127.0.0.1:5433");
  });

  it("falls back to the error code, the name, or the value itself", () => {
    expect(describeError(new Error("boom"))).toBe("boom");
    expect(describeError(Object.assign(new Error(""), { code: "ETIMEDOUT" }))).toBe("ETIMEDOUT");
    expect(describeError(new TypeError(""))).toBe("TypeError");
    expect(describeError("plain string")).toBe("plain string");
  });
});
