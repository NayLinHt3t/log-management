import type { Source } from "./schema";

export interface ParsedFile {
  records: unknown[];
  format: "json" | "ndjson" | "cloudtrail" | "csv" | "lines";
  sourceHint?: Source;
  errors: { line: number; error: string }[];
}

/** Guess the source from a file name such as "aws_cloudtrail.json" or "m365-audit.ndjson". */
export function inferSourceFromName(name: string): Source | undefined {
  const n = name.toLowerCase().replace(/^.*[\\/]/, "");
  if (/cloudtrail|aws/.test(n)) return "aws";
  if (/m365|o365|office365|unified[-_]?audit/.test(n)) return "m365";
  if (/crowdstrike|falcon/.test(n)) return "crowdstrike";
  if (/windows|wineventlog|winevent|security[-_]?events?|active[-_]?directory|(^|[^a-z])ad([^a-z]|$)/.test(n))
    return "ad";
  if (/firewall|(^|[^a-z])fw([^a-z]|$)/.test(n)) return "firewall";
  if (/router|switch|network/.test(n)) return "network";
  if (/(^|[^a-z])api([^a-z]|$)/.test(n)) return "api";
  return undefined;
}

const setPath = (obj: Record<string, any>, path: string, value: unknown) => {
  const keys = path.split(".");
  let cur = obj;
  for (const k of keys.slice(0, -1)) {
    if (typeof cur[k] !== "object" || cur[k] === null) cur[k] = {};
    cur = cur[k];
  }
  cur[keys[keys.length - 1]] = value;
};

/** RFC 4180 CSV -> objects. Dotted headers ("cloud.region") become nested objects. */
export function parseCsv(text: string): Record<string, unknown>[] {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else inQuotes = false;
      } else field += c;
    } else if (c === '"') inQuotes = true;
    else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += c;
  }
  if (field !== "" || row.length) {
    row.push(field);
    rows.push(row);
  }
  const nonEmpty = rows.filter((r) => r.some((f) => f.trim() !== ""));
  if (nonEmpty.length < 2) return [];
  const [header, ...body] = nonEmpty;
  return body.map((r) => {
    const obj: Record<string, unknown> = {};
    header.forEach((h, i) => {
      const v = (r[i] ?? "").trim();
      if (h.trim() && v !== "") setPath(obj, h.trim(), v);
    });
    return obj;
  });
}

const ARRAY_KEYS = ["Records", "records", "events", "value", "data", "logs", "items"];

/**
 * Turns an uploaded/dropped file into records for the pipeline:
 *  - JSON array, single JSON object, or CloudTrail's {"Records": [...]}
 *  - NDJSON / JSON Lines
 *  - CSV with a header row
 *  - plain text: one syslog line per row (.log/.txt)
 */
export function parseFileContent(text: string, filename = ""): ParsedFile {
  const body = text.replace(/^﻿/, "");
  const lower = filename.toLowerCase();
  const sourceHint = inferSourceFromName(filename);
  const trimmed = body.trim();
  const errors: ParsedFile["errors"] = [];

  if (lower.endsWith(".csv")) return { records: parseCsv(body), format: "csv", sourceHint, errors };

  const asLines = () =>
    body
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter(Boolean);

  if (/\.(log|txt|syslog)$/.test(lower) && !trimmed.startsWith("{") && !trimmed.startsWith("[")) {
    return { records: asLines(), format: "lines", sourceHint, errors };
  }

  if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (Array.isArray(parsed)) return { records: parsed, format: "json", sourceHint, errors };
      for (const key of ARRAY_KEYS) {
        if (Array.isArray(parsed?.[key])) {
          const isCloudTrail = key === "Records" && parsed[key].some((r: any) => r?.eventSource);
          return {
            records: parsed[key],
            format: isCloudTrail ? "cloudtrail" : "json",
            sourceHint: isCloudTrail ? (sourceHint ?? "aws") : sourceHint,
            errors,
          };
        }
      }
      return { records: [parsed], format: "json", sourceHint, errors };
    } catch {
      // not a single JSON document -> try JSON Lines below
    }
    if (trimmed.startsWith("{")) {
      const records: unknown[] = [];
      body.split(/\r?\n/).forEach((line, i) => {
        const l = line.trim();
        if (!l) return;
        try {
          records.push(JSON.parse(l));
        } catch {
          errors.push({ line: i + 1, error: "invalid JSON" });
        }
      });
      return { records, format: "ndjson", sourceHint, errors };
    }
  }

  // Header-looking first line with commas -> CSV, otherwise one syslog message per line.
  const firstLine = trimmed.split(/\r?\n/, 1)[0] ?? "";
  if (firstLine.includes(",") && !firstLine.startsWith("<") && /^[\w".@ ,-]+$/.test(firstLine)) {
    return { records: parseCsv(body), format: "csv", sourceHint, errors };
  }
  return { records: asLines(), format: "lines", sourceHint, errors };
}
