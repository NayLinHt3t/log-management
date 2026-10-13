import { describe, it, expect } from "vitest";
import { buildEventWhere, QueryError, tokenize } from "../../packages/core/src/query";

describe("search query language", () => {
  it("builds parameterised SQL for fields, CIDR, comparisons and free text", () => {
    const w = buildEventWhere({
      tenant: "demoA",
      q: 'user:alice src_ip:10.0.0.0/8 severity:>=7 "DNS blocked"',
    });
    expect(w.where).toBe(
      "tenant = $1 AND username = $2 AND src_ip <<= $3::inet AND severity >= $4 AND raw::text ILIKE $5",
    );
    expect(w.params).toEqual(["demoA", "alice", "10.0.0.0/8", 7, "%DNS blocked%"]);
  });

  it("supports negation, wildcards, lists, tags and raw fields", () => {
    const w = buildEventWhere({ q: "-source:firewall host:WIN* event_type:a,b tag:ts_restamped raw.eventName:CreateUser" });
    expect(w.where).toContain("(source = $1) IS NOT TRUE");
    expect(w.where).toContain("host ILIKE $2");
    expect(w.where).toContain("event_type = ANY($3::text[])");
    expect(w.where).toContain("tags @> ARRAY[$4]::text[]");
    expect(w.where).toContain("raw @> $5::jsonb");
    expect(w.params[1]).toBe("WIN%");
    expect(w.params[4]).toBe('{"eventName":"CreateUser"}');
  });

  it("ip: matches source or destination", () => {
    const w = buildEventWhere({ q: "ip:8.8.8.8" });
    expect(w.where).toBe("(src_ip = $1::inet OR dst_ip = $2::inet)");
  });

  it("treats unknown prefixes such as URLs as free text and escapes LIKE wildcards", () => {
    const w = buildEventWhere({ q: "http://evil.example/100%_off" });
    expect(w.params).toEqual(["%http://evil.example/100\\%\\_off%"]);
  });

  it("rejects invalid IPs and numbers with a 400-style error", () => {
    expect(() => buildEventWhere({ q: "src_ip:999.1.1.1" })).toThrow(QueryError);
    expect(() => buildEventWhere({ q: "severity:high" })).toThrow(QueryError);
  });

  it("tokenizes quoted values", () => {
    expect(tokenize('user:"demo\\\\eve" -x')).toMatchObject([
      { field: "user", value: "demo\\eve", quoted: true, neg: false },
      { value: "x", neg: true },
    ]);
  });
});
