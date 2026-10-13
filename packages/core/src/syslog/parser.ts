import { parseKv, looksLikeFirewall, kvGet } from "./kv";
import { parseCef, type CefEvent } from "./cef";

const MONTHS = [
  "Jan",
  "Feb",
  "Mar",
  "Apr",
  "May",
  "Jun",
  "Jul",
  "Aug",
  "Sep",
  "Oct",
  "Nov",
  "Dec",
];

// RFC 3164 (BSD): <PRI>Mmm dd hh:mm:ss HOST CONTENT
const RFC3164_RE =
  /^<(\d{1,3})>(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(.*)$/s;
// RFC 3164 with an ISO timestamp (rsyslog forwarding format): <PRI>2026-10-12T10:00:00Z HOST CONTENT
const ISO3164_RE = /^<(\d{1,3})>(\d{4}-\d{2}-\d{2}T\S+)\s+(\S+)\s+(.*)$/s;
// RFC 5424: <PRI>VERSION TIMESTAMP HOST APP PROCID MSGID SD [MSG]   (what `logger -n` sends)
const RFC5424_RE = /^<(\d{1,3})>(\d{1,2}) (\S+) (\S+) (\S+) (\S+) (\S+) ?(.*)$/s;
// "sshd[123]: message" style tag at the start of the content
const TAG_RE = /^([A-Za-z0-9_\-./]{1,48})(?:\[([^\]]{1,32})\])?:\s?(.*)$/s;

export type TimestampMode = "event" | "receive" | "auto";

export interface ParseOptions {
  now?: Date; // injectable for tests
  useReceiveTime?: boolean; // kept for compatibility; same as timestampMode "receive"
  /**
   * event   = trust the timestamp inside the message
   * receive = stamp with arrival time
   * auto    = trust it only when it carries a year and time zone (RFC 5424 / ISO),
   *           because RFC 3164 timestamps have neither
   */
  timestampMode?: TimestampMode;
}

export interface SyslogRecord {
  tenant: string;
  source: "firewall" | "network";
  "@timestamp": string;
  host?: string;
  syslog: {
    facility: number;
    severity: number;
    format: "rfc3164" | "rfc5424" | "unknown";
    timestamp?: string; // the timestamp text as sent by the device
    app?: string;
    pid?: string;
    msgid?: string;
    sd?: Record<string, Record<string, string>>;
  };
  kv: Record<string, string>;
  cef?: Omit<CefEvent, "ext">;
  message: string;
  raw: string;
  unparsed?: boolean;
}

function parseStructuredData(s: string) {
  const sd: Record<string, Record<string, string>> = {};
  let i = 0;
  while (s[i] === "[") {
    let j = i + 1;
    let inQuote = false;
    for (; j < s.length; j++) {
      const c = s[j];
      if (c === "\\") {
        j++;
        continue;
      }
      if (c === '"') inQuote = !inQuote;
      else if (c === "]" && !inQuote) break;
    }
    const element = s.slice(i + 1, j);
    const id = /^(\S+)/.exec(element)?.[1] ?? "sd";
    const params: Record<string, string> = {};
    for (const m of element.matchAll(/([^\s=]+)="((?:[^"\\]|\\.)*)"/g)) {
      params[m[1]] = m[2].replace(/\\(["\\\]])/g, "$1");
    }
    sd[id] = params;
    i = j + 1;
  }
  return { sd, rest: s.slice(i).replace(/^ /, "") };
}

/** Splits the free-form part into tag, key=value pairs and CEF header. */
function parseContent(content: string, isRfc3164: boolean) {
  let app: string | undefined;
  let pid: string | undefined;
  let message = content.replace(/^﻿/, "").trim();

  const cef = parseCef(message);
  if (!cef && isRfc3164) {
    const t = TAG_RE.exec(message);
    if (t) {
      app = t[1];
      pid = t[2];
      message = t[3].trim();
    }
  }
  const kv = cef ? cef.ext : parseKv(message);
  // UFW/iptables put the verdict in a prefix: "[UFW BLOCK] IN=eth0 ... SRC=..."
  if (!cef && kv.action === undefined) {
    if (/\b(BLOCK|DROP|DENY|REJECT)\b/.test(message)) kv.action = "deny";
    else if (/\b(ALLOW|ACCEPT)\b/.test(message) && (kv.SRC || kv.src)) kv.action = "allow";
  }
  let cefHeader: SyslogRecord["cef"];
  if (cef) {
    const { ext: _ext, ...header } = cef;
    cefHeader = header;
    if (cef.ext.act === undefined && /deny|block|drop/i.test(cef.name)) kv.act = "deny";
  }
  const source: SyslogRecord["source"] =
    looksLikeFirewall(kv) || (cef !== null && (kvGet(kv, "src") || kvGet(kv, "dst")))
      ? "firewall"
      : "network";
  return { app, pid, message, kv, cef: cefHeader, source };
}

function pickTime(
  mode: TimestampMode,
  hasZone: boolean,
  eventTime: Date | undefined,
  now: Date,
) {
  if (!eventTime || isNaN(eventTime.getTime())) return now;
  if (mode === "receive") return now;
  if (mode === "auto" && !hasZone) return now;
  return eventTime;
}

export function parseSyslog(
  line: string,
  tenant: string,
  opts: ParseOptions = {},
): SyslogRecord {
  const now = opts.now ?? new Date();
  const mode: TimestampMode = opts.timestampMode ?? (opts.useReceiveTime ? "receive" : "event");
  const trimmed = line.replace(/[\r\n\0]+$/, "").trim();

  let m = RFC5424_RE.exec(trimmed);
  if (m && /^\d{1,2}$/.test(m[2]) && (m[3] === "-" || /^\d{4}-\d{2}-\d{2}T/.test(m[3]))) {
    const pri = Number(m[1]);
    const { sd, rest } = parseStructuredData(m[8] === "-" || m[8].startsWith("- ") ? m[8].slice(2) : m[8]);
    const content = parseContent(rest, false);
    const eventTime = m[3] === "-" ? undefined : new Date(m[3]);
    return {
      tenant,
      source: content.source,
      "@timestamp": pickTime(mode, true, eventTime, now).toISOString(),
      host: m[4] === "-" ? undefined : m[4],
      syslog: {
        facility: pri >> 3,
        severity: pri & 7,
        format: "rfc5424",
        timestamp: m[3] === "-" ? undefined : m[3],
        app: m[5] === "-" ? undefined : m[5],
        pid: m[6] === "-" ? undefined : m[6],
        msgid: m[7] === "-" ? undefined : m[7],
        ...(Object.keys(sd).length ? { sd } : {}),
      },
      kv: content.kv,
      ...(content.cef ? { cef: content.cef } : {}),
      message: content.message,
      raw: trimmed,
    };
  }

  m = ISO3164_RE.exec(trimmed);
  if (m) {
    const pri = Number(m[1]);
    const content = parseContent(m[4], true);
    const eventTime = new Date(m[2]);
    const hasZone = /(Z|[+-]\d{2}:?\d{2})$/.test(m[2]);
    return {
      tenant,
      source: content.source,
      "@timestamp": pickTime(mode, hasZone, eventTime, now).toISOString(),
      host: m[3],
      syslog: {
        facility: pri >> 3,
        severity: pri & 7,
        format: "rfc3164",
        timestamp: m[2],
        app: content.app,
        pid: content.pid,
      },
      kv: content.kv,
      ...(content.cef ? { cef: content.cef } : {}),
      message: content.message,
      raw: trimmed,
    };
  }

  m = RFC3164_RE.exec(trimmed);
  if (!m) throw new Error("not a syslog line");

  const pri = Number(m[1]);
  const [mon, day, hh, mm, ss] = [MONTHS.indexOf(m[2]), +m[3], +m[4], +m[5], +m[6]];
  if (mon < 0) throw new Error("not a syslog line");
  let host: string | undefined = m[7];
  let rest = m[8];
  if (host.includes("=")) {
    // no HOSTNAME field: "<134>Aug 20 12:44:56 vendor=demo ..."
    rest = `${host} ${rest}`;
    host = undefined;
  }

  // Syslog (RFC 3164) has no year and no timezone: assume current year and UTC.
  let ts = new Date(Date.UTC(now.getUTCFullYear(), mon, day, hh, mm, ss));
  if (ts.getTime() > now.getTime() + 86_400_000) {
    ts = new Date(Date.UTC(now.getUTCFullYear() - 1, mon, day, hh, mm, ss)); // Dec log read in Jan
  }

  const content = parseContent(rest, true);
  return {
    tenant,
    source: content.source,
    "@timestamp": pickTime(mode, false, ts, now).toISOString(),
    host,
    syslog: {
      facility: pri >> 3,
      severity: pri & 7,
      format: "rfc3164",
      timestamp: `${m[2]} ${m[3]} ${m[4]}:${m[5]}:${m[6]}`,
      app: content.app,
      pid: content.pid,
    },
    kv: content.kv,
    ...(content.cef ? { cef: content.cef } : {}),
    message: content.message,
    raw: trimmed,
  };
}

/**
 * Never throws: anything that is not valid syslog (e.g. `echo hello | nc -u host 514`)
 * is kept as a generic network event instead of being dropped.
 */
export function parseSyslogLoose(
  line: string,
  tenant: string,
  opts: ParseOptions = {},
): SyslogRecord {
  try {
    return parseSyslog(line, tenant, opts);
  } catch {
    const now = opts.now ?? new Date();
    const trimmed = line.replace(/[\r\n\0]+$/, "").trim();
    const pri = /^<(\d{1,3})>/.exec(trimmed);
    const body = pri ? trimmed.slice(pri[0].length) : trimmed;
    const content = parseContent(body, true);
    const p = pri ? Number(pri[1]) : 13; // RFC 3164 §4.3.3: no PRI -> user.notice
    return {
      tenant,
      source: content.source,
      "@timestamp": now.toISOString(),
      syslog: { facility: p >> 3, severity: p & 7, format: "unknown", app: content.app },
      kv: content.kv,
      ...(content.cef ? { cef: content.cef } : {}),
      message: content.message,
      raw: trimmed,
      unparsed: true,
    };
  }
}

/** Splits a TCP/UDP payload into syslog messages (newline framing). */
export const splitLines = (payload: string) =>
  payload
    .split(/\r?\n/)
    .map((l) => l.replace(/\0/g, ""))
    .filter((l) => l.trim() !== "");
