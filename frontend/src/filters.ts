import { useCallback, useMemo } from "react";
import { useSearchParams } from "react-router-dom";

// Filters live in the URL so every view is shareable and drill-down links just navigate.
export const PRESETS = [
  { id: "15m", label: "15m", ms: 15 * 60_000, title: "Last 15 minutes" },
  { id: "1h", label: "1h", ms: 3600_000, title: "Last hour" },
  { id: "6h", label: "6h", ms: 6 * 3600_000, title: "Last 6 hours" },
  { id: "24h", label: "24h", ms: 24 * 3600_000, title: "Last 24 hours" },
  { id: "7d", label: "7d", ms: 7 * 86_400_000, title: "Last 7 days" },
] as const;
export type PresetId = (typeof PRESETS)[number]["id"] | "custom";

export interface Filters {
  range: PresetId;
  from?: string; // ISO, custom range only
  to?: string;
  tenant: string; // "" = all tenants the user may see
  sources: string[];
  q: string;
}

export function readFilters(p: URLSearchParams): Filters {
  const range = (p.get("range") as PresetId) || "24h";
  return {
    range: PRESETS.some((x) => x.id === range) || range === "custom" ? range : "24h",
    from: p.get("from") ?? undefined,
    to: p.get("to") ?? undefined,
    tenant: p.get("tenant") ?? "",
    sources: (p.get("source") ?? "").split(",").filter(Boolean),
    q: p.get("q") ?? "",
  };
}

export function toParams(f: Filters): URLSearchParams {
  const p = new URLSearchParams();
  if (f.range !== "24h") p.set("range", f.range);
  if (f.range === "custom") {
    if (f.from) p.set("from", f.from);
    if (f.to) p.set("to", f.to);
  }
  if (f.tenant) p.set("tenant", f.tenant);
  if (f.sources.length) p.set("source", f.sources.join(","));
  if (f.q) p.set("q", f.q);
  return p;
}

/** Absolute time window for an API call, computed at call time for relative presets. */
export function timeWindow(f: Filters): { from: string; to: string; spanMs: number } {
  if (f.range === "custom" && f.from && f.to) {
    const from = new Date(f.from);
    const to = new Date(f.to);
    return { from: from.toISOString(), to: to.toISOString(), spanMs: to.getTime() - from.getTime() };
  }
  const preset = PRESETS.find((x) => x.id === f.range) ?? PRESETS[3];
  const to = new Date();
  return { from: new Date(to.getTime() - preset.ms).toISOString(), to: to.toISOString(), spanMs: preset.ms };
}

export function apiQuery(f: Filters) {
  const w = timeWindow(f);
  return {
    from: w.from,
    to: w.to,
    tenant: f.tenant || undefined,
    source: f.sources.length ? f.sources.join(",") : undefined,
    q: f.q || undefined,
  };
}

export function describeRange(f: Filters) {
  if (f.range === "custom" && f.from && f.to) return "in the selected range";
  const p = PRESETS.find((x) => x.id === f.range) ?? PRESETS[3];
  return `in the ${p.title.toLowerCase()}`;
}

/** Adds a field:value term to a query, quoting values with spaces. */
export function addTerm(q: string, field: string, value: string) {
  const v = /[\s"]/.test(value) ? `"${value.replace(/(["\\])/g, "\\$1")}"` : value;
  const term = `${field}:${v}`;
  if (q.split(/\s+/).includes(term)) return q;
  return q ? `${q} ${term}` : term;
}

export function useFilters() {
  const [params, setParams] = useSearchParams();
  const filters = useMemo(() => readFilters(params), [params]);
  const setFilters = useCallback(
    (patch: Partial<Filters>) => setParams(toParams({ ...readFilters(params), ...patch })),
    [params, setParams],
  );
  return { filters, setFilters };
}

/** Link to another page carrying the current filters plus overrides. */
export function linkWith(path: string, f: Filters, patch: Partial<Filters> = {}) {
  const s = toParams({ ...f, ...patch }).toString();
  return s ? `${path}?${s}` : path;
}
