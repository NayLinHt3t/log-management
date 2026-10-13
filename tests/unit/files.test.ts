import { describe, it, expect } from "vitest";
import { parseFileContent, parseCsv, inferSourceFromName } from "../../packages/core/src/files";

describe("file parsing", () => {
  it("unwraps CloudTrail's {Records: [...]} and hints the aws source", () => {
    const f = parseFileContent(
      JSON.stringify({ Records: [{ eventSource: "iam.amazonaws.com", eventName: "CreateUser" }] }),
      "upload.json",
    );
    expect(f.format).toBe("cloudtrail");
    expect(f.sourceHint).toBe("aws");
    expect(f.records).toHaveLength(1);
  });

  it("reads NDJSON and reports bad lines", () => {
    const f = parseFileContent('{"a":1}\nnot json\n{"b":2}\n', "events.ndjson");
    expect(f.format).toBe("ndjson");
    expect(f.records).toHaveLength(2);
    expect(f.errors).toEqual([{ line: 2, error: "invalid JSON" }]);
  });

  it("reads CSV with quoted fields and dotted headers", () => {
    const rows = parseCsv('EventID,TargetUserName,cloud.region,msg\n4625,eve,ap-southeast-1,"a, ""quoted"" value"\n');
    expect(rows).toEqual([
      { EventID: "4625", TargetUserName: "eve", cloud: { region: "ap-southeast-1" }, msg: 'a, "quoted" value' },
    ]);
  });

  it("treats .log files as one syslog message per line", () => {
    const f = parseFileContent("<134>Aug 20 12:44:56 fw01 action=deny\n\n<134>Aug 20 12:44:57 fw01 action=allow\n", "fw.log");
    expect(f.format).toBe("lines");
    expect(f.records).toHaveLength(2);
  });

  it("infers the source from common file names", () => {
    expect(inferSourceFromName("aws_cloudtrail.json")).toBe("aws");
    expect(inferSourceFromName("m365-audit.json")).toBe("m365");
    expect(inferSourceFromName("ad_security_events.csv")).toBe("ad");
    expect(inferSourceFromName("upload.json")).toBeUndefined();
  });
});
