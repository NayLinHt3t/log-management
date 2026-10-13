import { EventSchema, NormalizedEvent, SOURCES, type Source } from "../schema";
import { normApi } from "./api";
import { normCrowdstrike } from "./crowdstrike";
import { normAws } from "./aws";
import { normM365 } from "./m365";
import { normAd } from "./ad";
import { normFirewall } from "./firewall";
import { normNetwork } from "./network";
import { toDate } from "./util";

const NORMALIZERS: Record<Source, (p: any) => Record<string, unknown>> = {
  api: normApi,
  crowdstrike: normCrowdstrike,
  aws: normAws,
  m365: normM365,
  ad: normAd,
  firewall: normFirewall,
  network: normNetwork,
};

// Friendly names people tend to use for the same source.
const SOURCE_ALIASES: Record<string, Source> = {
  cloudtrail: "aws",
  o365: "m365",
  office365: "m365",
  microsoft365: "m365",
  windows: "ad",
  wineventlog: "ad",
  "windows-security": "ad",
  falcon: "crowdstrike",
  cs: "crowdstrike",
  fw: "firewall",
  syslog: "network",
  router: "network",
};

export const resolveSource = (s: unknown): Source | undefined => {
  if (typeof s !== "string") return undefined;
  const v = s.trim().toLowerCase();
  return (SOURCES as readonly string[]).includes(v) ? (v as Source) : SOURCE_ALIASES[v];
};

/** Guesses the source from the record's shape when it does not say. */
export function detectSource(p: any): Source {
  if (p?.syslog && p?.kv) return p.source === "firewall" ? "firewall" : "network";
  if (p?.eventSource && p?.eventName) return "aws"; // CloudTrail
  if (p?.Operation && (p?.Workload !== undefined || p?.RecordType !== undefined)) return "m365";
  if (
    p?.EventID !== undefined ||
    p?.EventId !== undefined ||
    p?.event_id !== undefined ||
    p?.winlog !== undefined
  )
    return "ad";
  if (p?.metadata?.eventType || p?.event?.DetectName || p?.DetectName) return "crowdstrike";
  return "api";
}

const LIMITS: Record<string, number> = { event_type: 200, event_subtype: 1000 };

/** Drops null/empty fields and trims over-long strings so validation errors stay meaningful. */
function clean(e: Record<string, unknown>) {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(e)) {
    if (v === null || v === undefined || v === "") continue;
    if (typeof v === "string") {
      const max = LIMITS[k] ?? 2000;
      out[k] = v.length > max ? v.slice(0, max) : v;
    } else out[k] = v;
  }
  return out;
}

export interface NormalizeOptions {
  now?: Date; // used when the record carries no timestamp
  tenant?: string; // decided by the pipeline; keeps `raw` exactly as received
}

export function normalize(
  payload: any,
  sourceHint?: string,
  opts: NormalizeOptions = {},
): NormalizedEvent {
  const explicit = payload?.source;
  const source =
    explicit !== undefined
      ? resolveSource(explicit)
      : (resolveSource(sourceHint) ?? detectSource(payload));
  if (!source) throw new Error(`unknown source: ${explicit ?? sourceHint}`);

  const e = clean(NORMALIZERS[source](payload));
  if (opts.tenant !== undefined) e.tenant = opts.tenant;
  const tags = Array.isArray(e.tags) ? [...(e.tags as string[])] : [];
  if (e.ts === undefined) {
    e.ts = opts.now ?? new Date();
  } else {
    const d = toDate(e.ts);
    if (d) e.ts = d;
    else {
      e.ts = opts.now ?? new Date(); // keep the event; the original value is still in raw
      tags.push("ts_unparsed");
    }
  }
  e.tags = tags;
  return EventSchema.parse(e); // throws on invalid data
}

export { resolveSource as normalizeSourceName };
