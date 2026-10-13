import { isIP } from "node:net";

/** Trimmed non-empty string, or undefined. Numbers/booleans are stringified. */
export const str = (v: unknown): string | undefined => {
  if (v === null || v === undefined) return undefined;
  if (typeof v === "string") {
    const s = v.trim();
    return s === "" || s === "-" ? undefined : s;
  }
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  return undefined;
};

/** First argument that is a usable string. */
export const first = (...vals: unknown[]): string | undefined => {
  for (const v of vals) {
    const s = str(v);
    if (s !== undefined) return s;
  }
  return undefined;
};

/**
 * Accepts "1.2.3.4", "1.2.3.4:5678", "[2001:db8::1]:443", "2001:db8::1".
 * Returns the bare IP, or undefined for anything else ("AWS Internal", "-", hostnames).
 */
export const ip = (v?: unknown): string | undefined => {
  let s = str(v);
  if (!s) return undefined;
  if (isIP(s)) return s;
  const bracketed = /^\[([0-9a-fA-F:.]+)\](?::\d+)?$/.exec(s);
  if (bracketed && isIP(bracketed[1])) return bracketed[1];
  const v4port = /^(\d{1,3}(?:\.\d{1,3}){3}):\d+$/.exec(s);
  if (v4port && isIP(v4port[1])) return v4port[1];
  s = s.replace(/%.*$/, ""); // fe80::1%eth0 -> fe80::1
  return isIP(s) ? s : undefined;
};

/** Integer from a number or a numeric string, else undefined. */
export const num = (v?: unknown): number | undefined => {
  if (typeof v === "number") return Number.isInteger(v) ? v : undefined;
  const s = str(v);
  if (s === undefined) return undefined;
  const n = Number(s);
  return Number.isInteger(n) ? n : undefined;
};

export const port = (v?: unknown): number | undefined => {
  const n = num(v);
  return n !== undefined && n >= 0 && n <= 65535 ? n : undefined;
};

export const clampSeverity = (n: number) =>
  Math.max(0, Math.min(10, Math.round(n)));

// syslog severity 0 (emergency) .. 7 (debug) -> schema severity 0..10
export const SYSLOG_SEV = [10, 9, 8, 7, 5, 3, 2, 1];

/**
 * Parses ISO-8601 strings, epoch seconds/milliseconds and Date objects.
 * Timestamps without a zone (e.g. M365 "CreationTime") are treated as UTC.
 */
export const toDate = (v: unknown): Date | undefined => {
  if (v === null || v === undefined || v === "") return undefined;
  if (v instanceof Date) return isNaN(v.getTime()) ? undefined : v;
  if (typeof v === "number" || (typeof v === "string" && /^\d{10,13}$/.test(v))) {
    const n = Number(v);
    const d = new Date(n < 1e12 ? n * 1000 : n);
    return isNaN(d.getTime()) ? undefined : d;
  }
  if (typeof v !== "string") return undefined;
  let s = v.trim();
  // .NET JSON dates from PowerShell ConvertTo-Json: "/Date(1692529871000)/"
  const dotnet = /^\/Date\((-?\d+)(?:[+-]\d{4})?\)\/$/.exec(s);
  if (dotnet) return new Date(Number(dotnet[1]));
  // "2025-08-20T10:05:00" or "2025-08-20 10:05:00" without zone -> UTC
  if (/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?$/.test(s)) {
    s = s.replace(" ", "T") + "Z";
  }
  const d = new Date(s);
  return isNaN(d.getTime()) ? undefined : d;
};

/** Case-insensitive lookup of the first present key. */
export const getCI = (obj: Record<string, unknown> | undefined, ...keys: string[]) => {
  if (!obj) return undefined;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null && obj[k] !== "") return obj[k];
  }
  const lower = new Map(Object.keys(obj).map((k) => [k.toLowerCase(), k]));
  for (const k of keys) {
    const real = lower.get(k.toLowerCase());
    if (real !== undefined && obj[real] !== undefined && obj[real] !== null && obj[real] !== "")
      return obj[real];
  }
  return undefined;
};

export const outcomeFrom = (v: unknown): "success" | "failure" | undefined => {
  const s = str(v)?.toLowerCase();
  if (!s) return undefined;
  if (/^(success|succeeded|successful|ok|true|partiallysucceeded|allowed|0x0)$/.test(s))
    return "success";
  if (/^(fail|failed|failure|false|denied|error|blocked)$/.test(s) || s.startsWith("0xc"))
    return "failure";
  return undefined;
};

export const compact = (arr: (string | false | null | undefined)[]) =>
  arr.filter((x): x is string => typeof x === "string" && x !== "");
