import { parseKv } from "./kv";

// ArcSight Common Event Format, used by many firewalls/IDS when sending syslog:
// CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
export interface CefEvent {
  version: string;
  vendor: string;
  product: string;
  deviceVersion: string;
  signatureId: string;
  name: string;
  severity: number; // already on the 0..10 scale
  ext: Record<string, string>;
}

const SEVERITY_WORDS: Record<string, number> = {
  unknown: 5,
  low: 3,
  medium: 5,
  high: 8,
  "very-high": 10,
};

/** Returns null when the text does not contain a CEF record. */
export function parseCef(text: string): CefEvent | null {
  const start = text.indexOf("CEF:");
  if (start < 0) return null;
  const body = text.slice(start + 4);

  // split the 7 header fields on unescaped pipes; the rest is the extension
  const parts: string[] = [];
  let cur = "";
  let i = 0;
  for (; i < body.length && parts.length < 7; i++) {
    const c = body[i];
    if (c === "\\" && i + 1 < body.length) {
      cur += body[i + 1];
      i++;
    } else if (c === "|") {
      parts.push(cur);
      cur = "";
    } else {
      cur += c;
    }
  }
  if (parts.length < 7) return null;
  const extension = body.slice(i);

  const ext = parseKv(extension);
  for (const k of Object.keys(ext)) {
    ext[k] = ext[k].replace(/\\=/g, "=").replace(/\\n/g, "\n").replace(/\\\\/g, "\\");
  }

  const [version, vendor, product, deviceVersion, signatureId, name, sevText] = parts;
  const sevNum = Number(sevText);
  const severity = Number.isFinite(sevNum)
    ? Math.max(0, Math.min(10, Math.round(sevNum)))
    : (SEVERITY_WORDS[sevText.trim().toLowerCase()] ?? 5);

  // CEF custom strings: cs1Label=Rule cs1=Block-DNS -> rule=Block-DNS
  for (let n = 1; n <= 6; n++) {
    const label = ext[`cs${n}Label`];
    const value = ext[`cs${n}`];
    if (label && value !== undefined) ext[label.replace(/\s+/g, "_").toLowerCase()] = value;
  }

  return { version, vendor, product, deviceVersion, signatureId, name, severity, ext };
}
