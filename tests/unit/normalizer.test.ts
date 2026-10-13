import { describe, it, expect } from "vitest";
import { normalize } from "../../packages/core/src/normalizers";

describe("normalizers", () => {
  it("api: maps ip to src_ip and user to username", () => {
    const e = normalize({
      tenant: "demoA",
      source: "api",
      event_type: "app_login_failed",
      user: "alice",
      ip: "203.0.113.7",
      reason: "wrong_password",
      "@timestamp": "2025-08-20T07:20:00Z",
    });
    expect(e.src_ip).toBe("203.0.113.7");
    expect(e.username).toBe("alice");
  });

  it("crowdstrike: quarantine becomes alert, original kept in raw", () => {
    const e = normalize({
      tenant: "demoA",
      source: "crowdstrike",
      event_type: "malware_detected",
      host: "WIN10-01",
      process: "powershell.exe",
      severity: 8,
      sha256: "abc",
      action: "quarantine",
      "@timestamp": "2025-08-20T08:00:00Z",
    });
    expect(e.action).toBe("alert");
    expect((e.raw as any).action).toBe("quarantine");
  });

  it("aws: flattens cloud fields", () => {
    const e = normalize({
      tenant: "demoB",
      source: "aws",
      cloud: {
        service: "iam",
        account_id: "123456789012",
        region: "ap-southeast-1",
      },
      event_type: "CreateUser",
      user: "admin",
      "@timestamp": "2025-08-20T09:10:00Z",
    });
    expect(e.cloud_account_id).toBe("123456789012");
    expect(e.action).toBe("create");
  });

  it("m365: failed status becomes UserLoginFailed", () => {
    const e = normalize({
      tenant: "demoB",
      source: "m365",
      event_type: "UserLoggedIn",
      user: "bob@demo.local",
      ip: "198.51.100.23",
      status: "Failed",
      "@timestamp": "2025-08-20T10:05:00Z",
    });
    expect(e.event_type).toBe("UserLoginFailed");
  });

  it("ad: 4625 is a failed login", () => {
    const e = normalize({
      tenant: "demoA",
      source: "ad",
      event_id: 4625,
      event_type: "LogonFailed",
      user: "demo\\eve",
      host: "DC01",
      ip: "203.0.113.77",
      logon_type: 3,
      "@timestamp": "2025-08-20T11:11:11Z",
    });
    expect(e.action).toBe("login");
    expect(e.severity).toBe(5);
  });

  it("rejects unknown source and invalid IP", () => {
    expect(() => normalize({ source: "nope", tenant: "t" })).toThrow();
    expect(() =>
      normalize({
        tenant: "t",
        source: "api",
        event_type: "x",
        ip: "999.1.1.1",
        "@timestamp": "2025-08-20T07:20:00Z",
      }),
    ).toThrow();
  });
});

describe("native vendor formats", () => {
  it("aws: a real CloudTrail record (failed console login)", () => {
    const e = normalize(
      {
        eventVersion: "1.08",
        userIdentity: { type: "IAMUser", userName: "mallory", accountId: "123456789012", arn: "arn:aws:iam::123456789012:user/mallory" },
        eventTime: "2026-10-12T09:10:00Z",
        eventSource: "signin.amazonaws.com",
        eventName: "ConsoleLogin",
        awsRegion: "ap-southeast-1",
        sourceIPAddress: "203.0.113.99",
        responseElements: { ConsoleLogin: "Failure" },
        recipientAccountId: "123456789012",
      },
      undefined,
      { tenant: "demoB" },
    );
    expect(e.source).toBe("aws"); // detected from the record's shape
    expect(e.action).toBe("login");
    expect(e.outcome).toBe("failure");
    expect(e.username).toBe("mallory");
    expect(e.cloud_service).toBe("signin");
    expect(e.cloud_region).toBe("ap-southeast-1");
    expect(e.ts.toISOString()).toBe("2026-10-12T09:10:00.000Z");
  });

  it("aws: service principals in sourceIPAddress are not treated as IPs", () => {
    const e = normalize(
      { eventSource: "ec2.amazonaws.com", eventName: "RunInstances", sourceIPAddress: "autoscaling.amazonaws.com", eventTime: "2026-10-12T09:00:00Z" },
      undefined,
      { tenant: "demoB" },
    );
    expect(e.src_ip).toBeUndefined();
    expect(e.action).toBe("create");
  });

  it("m365: native Unified Audit Log record (UTC time without zone, IP with port)", () => {
    const e = normalize(
      {
        CreationTime: "2026-10-12T10:05:00",
        Operation: "UserLoginFailed",
        RecordType: 15,
        ResultStatus: "Failed",
        UserId: "bob@demo.local",
        ClientIP: "198.51.100.23:51234",
        Workload: "AzureActiveDirectory",
      },
      undefined,
      { tenant: "demoB" },
    );
    expect(e.source).toBe("m365");
    expect(e.outcome).toBe("failure");
    expect(e.src_ip).toBe("198.51.100.23");
    expect(e.ts.toISOString()).toBe("2026-10-12T10:05:00.000Z");
  });

  it("ad: flat Windows export and Winlogbeat shape", () => {
    const flat = normalize(
      { EventID: "4625", TimeCreated: "/Date(1791794400000)/", Computer: "DC01", TargetUserName: "eve", TargetDomainName: "DEMO", IpAddress: "203.0.113.77", LogonType: "3" },
      undefined,
      { tenant: "demoA" },
    );
    expect(flat.source).toBe("ad");
    expect(flat.username).toBe("DEMO\\eve");
    expect(flat.outcome).toBe("failure");
    expect(flat.tags).toContain("logon_type:3");
    expect(flat.ts.getTime()).toBe(1791794400000);

    const wlb = normalize(
      { "@timestamp": "2026-10-12T11:00:00Z", winlog: { event_id: "4740", computer_name: "DC02", event_data: { TargetUserName: "eve" } } },
      undefined,
      { tenant: "demoA" },
    );
    expect(wlb.event_type).toBe("AccountLockedOut");
    expect(wlb.severity).toBe(7);
    expect(wlb.host).toBe("DC02");
  });

  it("crowdstrike: Falcon streaming detection (severity 1-5 scaled to 0-10)", () => {
    const e = normalize(
      {
        metadata: { eventType: "DetectionSummaryEvent", eventCreationTime: 1791794400000 },
        event: { ComputerName: "WIN10-02", UserName: "eve", FileName: "mimikatz.exe", SHA256String: "deadbeef", Severity: 5, Tactic: "Credential Access", DetectName: "Credential Theft" },
      },
      undefined,
      { tenant: "demoA" },
    );
    expect(e.source).toBe("crowdstrike");
    expect(e.severity).toBe(10);
    expect(e.process).toBe("mimikatz.exe");
    expect(e.tags).toContain("tactic:Credential Access");
  });

  it("accepts source aliases such as cloudtrail and o365", () => {
    expect(normalize({ source: "o365", tenant: "t", Operation: "FileAccessed", "@timestamp": "2026-10-12T00:00:00Z" }).source).toBe("m365");
    expect(normalize({ source: "cloudtrail", tenant: "t", eventName: "ListBuckets", "@timestamp": "2026-10-12T00:00:00Z" }).source).toBe("aws");
  });

  it("uses the receive time when a record has no timestamp, and flags unparseable ones", () => {
    const now = new Date("2026-10-12T12:00:00Z");
    expect(normalize({ tenant: "t", source: "api", event_type: "x" }, undefined, { now }).ts).toEqual(now);
    const bad = normalize({ tenant: "t", source: "api", event_type: "x", "@timestamp": "yesterday-ish" }, undefined, { now });
    expect(bad.ts).toEqual(now);
    expect(bad.tags).toContain("ts_unparsed");
  });
});
