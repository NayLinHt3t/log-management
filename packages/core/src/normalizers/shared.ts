/** key=value view of a record: the parsed syslog kv, or the JSON object's scalar fields. */
export const asKv = (p: any): Record<string, string> => {
  if (p?.kv && typeof p.kv === "object") return p.kv;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(p ?? {})) {
    if (typeof v === "string" || typeof v === "number" || typeof v === "boolean")
      out[k] = String(v);
  }
  return out;
};

/** "Port scan detected" -> "port_scan_detected" */
export const slug = (s: string) =>
  s
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "")
    .slice(0, 100) || "event";
