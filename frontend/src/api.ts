// Typed client for the backend REST API (same origin: /api is proxied by Vite or Caddy).

export type Role = "admin" | "viewer";

export interface User {
  username: string;
  role: Role;
  tenant: string | null;
}

export interface EventRow {
  id: string;
  "@timestamp": string;
  ingested_at?: string;
  tenant: string;
  source: string;
  vendor?: string;
  product?: string;
  event_type: string;
  event_subtype?: string;
  severity: number;
  action?: string;
  outcome?: string;
  src_ip?: string;
  src_port?: number;
  dst_ip?: string;
  dst_port?: number;
  protocol?: string;
  user?: string;
  host?: string;
  process?: string;
  url?: string;
  http_method?: string;
  status_code?: number;
  rule_name?: string;
  rule_id?: string;
  cloud?: { account_id?: string; region?: string; service?: string };
  _tags: string[];
  raw: unknown;
}

export interface SearchResult {
  events: EventRow[];
  next_cursor: string | null;
  total: number | null;
  total_capped: boolean;
  took_ms: number;
  scope: string;
  from: string;
  to: string;
}

export interface KeyCount {
  key: string;
  count: number;
  source?: string;
}

export interface Summary {
  scope: string;
  from: string;
  to: string;
  bucket: string;
  took_ms: number;
  totals: {
    total: number;
    high_severity: number;
    failed_logins: number;
    denied: number;
    unique_src_ips: number;
    unique_users: number;
    open_alerts: number;
  };
  timeline: Array<Record<string, number | string>>;
  timeline_sources: string[];
  top_src_ips: KeyCount[];
  top_users: KeyCount[];
  top_event_types: KeyCount[];
  by_source: KeyCount[];
  by_severity: KeyCount[];
}

export interface Alert {
  id: string;
  rule_id: number | null;
  rule_name: string;
  tenant: string;
  group_by: string | null;
  group_key: string | null;
  severity: number;
  status: "open" | "acknowledged" | "closed";
  event_count: number;
  first_seen: string;
  last_seen: string;
  message: string;
  query: string | null;
  sample: Record<string, unknown>[];
  notify_status: string | null;
  notified_at: string | null;
  acknowledged_by: string | null;
  acknowledged_at: string | null;
  created_at: string;
}

export interface Rule {
  id: number;
  tenant: string | null;
  name: string;
  description: string | null;
  enabled: boolean;
  query: string;
  group_by: string | null;
  threshold: number;
  window_minutes: number;
  severity: number;
  webhook_url: string | null;
  created_by: string | null;
  open_alerts?: number;
}

export interface Tenant {
  id: string;
  name: string;
  retention_days: number | null;
  effective_retention_days: number;
  partitions: number;
  oldest_day: string | null;
}

export interface UserRow {
  id: number;
  username: string;
  role: Role;
  tenant: string | null;
  created_at: string;
  last_login_at: string | null;
}

export interface ApiKey {
  id: number;
  name: string;
  tenant: string | null;
  key_prefix: string;
  created_by: string | null;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
  key?: string;
}

export interface ServiceStatus {
  service: string;
  instance: string;
  started_at: string;
  last_seen: string;
  age_s: number;
  healthy: boolean;
  stats: Record<string, unknown>;
}

export interface SystemStatus {
  version: string;
  retention_days: number;
  late_event_policy: string;
  services: ServiceStatus[];
  partitions: { tenant: string; partitions: number; oldest_day: string; newest_day: string }[];
}

export interface IngestResult {
  accepted: number;
  rejected: number;
  restamped: number;
  errors: { index: number; error: string }[];
  file?: string;
  format?: string;
}

export class ApiError extends Error {
  status: number;
  details?: string[];
  constructor(status: number, message: string, details?: string[]) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const TOKEN_KEY = "logmgmt.token";

export const tokenStore = {
  get(): string | null {
    try {
      return localStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set(token: string | null) {
    try {
      if (token) localStorage.setItem(TOKEN_KEY, token);
      else localStorage.removeItem(TOKEN_KEY);
    } catch {
      /* storage unavailable (private mode): session lasts until reload */
    }
  },
};

type Query = Record<string, string | number | undefined | null>;

export function buildQuery(q?: Query) {
  if (!q) return "";
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(q)) if (v !== undefined && v !== null && v !== "") p.set(k, String(v));
  const s = p.toString();
  return s ? `?${s}` : "";
}

let memoryToken: string | null = null;
export const setMemoryToken = (t: string | null) => {
  memoryToken = t;
};

export async function api<T>(
  path: string,
  opts: { method?: string; body?: unknown; query?: Query; form?: FormData; signal?: AbortSignal } = {},
): Promise<T> {
  const headers: Record<string, string> = {};
  const token = memoryToken ?? tokenStore.get();
  if (token) headers.authorization = `Bearer ${token}`;
  let body: BodyInit | undefined;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(opts.body);
  }
  const res = await fetch(`/api${path}${buildQuery(opts.query)}`, {
    method: opts.method ?? (body ? "POST" : "GET"),
    headers,
    body,
    signal: opts.signal,
  });
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: any = undefined;
  try {
    data = text ? JSON.parse(text) : undefined;
  } catch {
    data = text;
  }
  if (!res.ok) {
    if (res.status === 401 && token) window.dispatchEvent(new CustomEvent("auth:expired"));
    const msg = (data && typeof data === "object" && data.error) || `Request failed (${res.status})`;
    throw new ApiError(res.status, msg, data?.details);
  }
  return data as T;
}

/** Download helper for authenticated files (CSV export). */
export async function download(path: string, query: Query, filename: string) {
  const token = memoryToken ?? tokenStore.get();
  const res = await fetch(`/api${path}${buildQuery(query)}`, {
    headers: token ? { authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new ApiError(res.status, `Export failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
