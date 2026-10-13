/** Minimal Prometheus-style counters (no extra dependency needed for a handful of series). */
type Labels = Record<string, string | number>;

const key = (labels: Labels) =>
  Object.entries(labels)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}="${String(v).replace(/["\\\n]/g, "_")}"`)
    .join(",");

export class Counter {
  private values = new Map<string, number>();
  constructor(
    readonly name: string,
    readonly help: string,
  ) {}
  inc(labels: Labels = {}, n = 1) {
    const k = key(labels);
    this.values.set(k, (this.values.get(k) ?? 0) + n);
  }
  total() {
    let t = 0;
    for (const v of this.values.values()) t += v;
    return t;
  }
  render() {
    const lines = [`# HELP ${this.name} ${this.help}`, `# TYPE ${this.name} counter`];
    for (const [k, v] of this.values) lines.push(`${this.name}${k ? `{${k}}` : ""} ${v}`);
    return lines.join("\n");
  }
}

export class Metrics {
  httpRequests = new Counter("logmgmt_http_requests_total", "HTTP requests by route and status");
  httpSeconds = new Counter("logmgmt_http_request_seconds_total", "Total time spent serving HTTP requests");
  ingested = new Counter("logmgmt_api_ingest_events_total", "Events received by the API by channel and result");
  logins = new Counter("logmgmt_logins_total", "Login attempts by result");

  render() {
    return [this.httpRequests, this.httpSeconds, this.ingested, this.logins].map((c) => c.render()).join("\n");
  }

  snapshot() {
    return {
      http_requests: this.httpRequests.total(),
      ingest_events: this.ingested.total(),
      logins: this.logins.total(),
    };
  }
}

export const gauge = (name: string, help: string, rows: [Labels, number][]) =>
  [`# HELP ${name} ${help}`, `# TYPE ${name} gauge`, ...rows.map(([l, v]) => `${name}${Object.keys(l).length ? `{${key(l)}}` : ""} ${v}`)].join("\n");
