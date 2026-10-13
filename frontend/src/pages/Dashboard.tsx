import { useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type Alert, type EventRow, type KeyCount, type SearchResult, type Summary } from "../api";
import { useUser } from "../auth";
import { addTerm, apiQuery, describeRange, linkWith, timeWindow, useFilters } from "../filters";
import { fmtNum, fmtTime, relative, severityLevel } from "../format";
import { useLoader, usePref } from "../hooks";
import { sortSources, sourceColor, sourceLabel } from "../sources";
import { FilterBar } from "../components/FilterBar";
import { Timeline } from "../components/Timeline";
import { Empty, ErrorBanner, Severity } from "../components/ui";

/** One mono line per event: the original syslog text, or the key fields for JSON sources. */
export function summarize(e: EventRow) {
  const raw = e.raw as { message?: unknown } | null;
  // syslog: drop "<PRI>timestamp " so the line starts with the host and the payload
  if (raw && typeof raw.message === "string")
    return raw.message.replace(/^<\d{1,3}>(\d\s+)?(\d{4}-\d{2}-\d{2}T\S+|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+/, "");
  const parts = [e.event_type];
  if (e.user) parts.push(`user=${e.user}`);
  if (e.src_ip) parts.push(`src=${e.src_ip}`);
  if (e.dst_ip) parts.push(`dst=${e.dst_ip}${e.dst_port ? `:${e.dst_port}` : ""}`);
  if (e.host) parts.push(`host=${e.host}`);
  if (e.process) parts.push(`process=${e.process}`);
  return parts.join(" ");
}

function TopPanel({
  title,
  sub,
  items,
  onPick,
  withSource,
}: {
  title: string;
  sub: string;
  items: KeyCount[];
  onPick: (key: string) => void;
  withSource?: boolean;
}) {
  const max = Math.max(1, ...items.map((i) => i.count));
  return (
    <section className="panel" aria-label={title}>
      <div className="panel-head">
        <h2>{title}</h2>
        <span className="sub">{sub}</span>
      </div>
      <div className="panel-body">
        {items.length === 0 ? (
          <Empty title="Nothing yet">No events with this field in the current filters.</Empty>
        ) : (
          <ul className="toplist">
            {items.map((i) => (
              <li key={i.key}>
                <button type="button" onClick={() => onPick(i.key)} title={`Search for ${i.key}`}>
                  <span className="name">
                    {withSource && i.source && (
                      <span className="swatch" style={{ background: sourceColor(i.source) }} aria-label={sourceLabel(i.source)} />
                    )}
                    {i.key}
                  </span>
                  <span className="count">{fmtNum(i.count)}</span>
                  <span className="bar" aria-hidden="true">
                    <i style={{ width: `${(i.count / max) * 100}%` }} />
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

const SEVERITY_BANDS = [
  { key: "low", label: "Low (0-3)", color: "var(--bar-neutral)", q: "severity:<=3" },
  { key: "medium", label: "Medium (4-6)", color: "var(--warning)", q: "severity:4..6" },
  { key: "high", label: "High (7-8)", color: "var(--serious)", q: "severity:7..8" },
  { key: "critical", label: "Critical (9-10)", color: "var(--critical)", q: "severity:>=9" },
];

export function Dashboard() {
  const user = useUser();
  const navigate = useNavigate();
  const { filters } = useFilters();
  const [auto, setAuto] = usePref("logmgmt.autorefresh", true);

  const summary = useLoader(
    (signal) => api<Summary>("/stats/summary", { query: apiQuery(filters), signal }),
    [filters],
    auto ? 15_000 : undefined,
  );
  const latest = useLoader(
    (signal) => api<SearchResult>("/events", { query: { ...apiQuery(filters), limit: 8 }, signal }),
    [filters],
    auto ? 5_000 : undefined,
  );

  const recentAlerts = useLoader(
    (signal) =>
      api<{ alerts: Alert[] }>("/alerts", { query: { status: "all", limit: 5, tenant: filters.tenant || undefined }, signal }),
    [filters.tenant],
    auto ? 15_000 : undefined,
  );

  // highlight lines that arrived since the previous refresh
  const seen = useRef<Set<string> | null>(null);
  const [fresh, setFresh] = useState<Set<string>>(new Set());
  useEffect(() => {
    if (!latest.data) return;
    const ids = latest.data.events.map((e) => e.id);
    const before = seen.current;
    seen.current = new Set(ids);
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (before) setFresh(new Set(ids.filter((id) => !before.has(id))));
  }, [latest.data]);

  const s = summary.data;
  const span = timeWindow(filters).spanMs;
  const search = (q: string) => navigate(linkWith("/search", filters, { q: q.trim() }));
  const drill = (field: string, value: string) => search(addTerm(filters.q, field, value));

  const scope = user.tenant
    ? `tenant ${user.tenant}`
    : filters.tenant
      ? `tenant ${filters.tenant}`
      : "all tenants";
  const sourcesText = filters.sources.length
    ? filters.sources.map(sourceLabel).join(", ")
    : `${s?.by_source.length ?? 0} source${s?.by_source.length === 1 ? "" : "s"}`;
  const sevCounts = new Map((s?.by_severity ?? []).map((r) => [r.key, r.count]));
  const sevTotal = [...sevCounts.values()].reduce((a, b) => a + b, 0);
  const refreshAll = () => {
    void summary.reload();
    void latest.reload();
  };

  return (
    <>
      <FilterBar onRefresh={refreshAll} refreshing={summary.loading} />
      <ErrorBanner error={summary.error} />

      <section className="hero">
        <div className="panel hero-main">
          <div className="hero-figure">
            <strong>{s ? fmtNum(s.totals.total) : "–"}</strong>
            <span>
              events {describeRange(filters)} from {sourcesText}, {scope}
              {filters.q && (
                <>
                  , matching <code>{filters.q}</code>
                </>
              )}
            </span>
          </div>
          {s && s.totals.total === 0 ? (
            <Empty title="No events in this window">
              Widen the time range, or <Link to="/sources">send some logs</Link> (syslog, HTTP or a file).
            </Empty>
          ) : (
            <Timeline
              data={s?.timeline ?? []}
              sources={s?.timeline_sources ?? []}
              spanMs={span}
              bucket={s?.bucket ?? ""}
              stale={summary.loading && Boolean(s)}
            />
          )}
          <div className="readout">
            <div>
              <span className="label">Failed logins</span>
              <button type="button" className="value" onClick={() => search(`${filters.q} action:login outcome:failure`)}>
                {fmtNum(s?.totals.failed_logins)}
              </button>
            </div>
            <div>
              <span className="label">High severity (7+)</span>
              <button type="button" className="value" onClick={() => search(`${filters.q} severity:>=7`)}>
                {fmtNum(s?.totals.high_severity)}
              </button>
            </div>
            <div>
              <span className="label">Denied connections</span>
              <button type="button" className="value" onClick={() => search(`${filters.q} action:deny`)}>
                {fmtNum(s?.totals.denied)}
              </button>
            </div>
            <div>
              <span className="label">Unique source IPs</span>
              <span className="value">{fmtNum(s?.totals.unique_src_ips)}</span>
            </div>
            <div>
              <span className="label">Open alerts</span>
              <Link to="/alerts" className={`value${s?.totals.open_alerts ? " alerting" : ""}`} style={{ textDecoration: "none" }}>
                {fmtNum(s?.totals.open_alerts)}
              </Link>
            </div>
          </div>
        </div>

        <aside className="panel tail" aria-label="Latest events">
          <div className="panel-head">
            <h2>
              <span className={`live-dot${auto ? "" : " paused"}`} aria-hidden="true" />
              Latest events
            </h2>
            <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAuto(!auto)} aria-pressed={!auto}>
              {auto ? "Pause" : "Resume"}
            </button>
          </div>
          <p className="muted" style={{ padding: "2px 16px 8px", fontSize: 12.5 }}>
            {auto ? "Refreshing every 5 seconds" : "Live updates paused"}
          </p>
          {latest.data && latest.data.events.length === 0 && <Empty title="Waiting for events" />}
          <ul className="tail-list">
            {(latest.data?.events ?? []).map((e) => (
              <li key={e.id} className={fresh.has(e.id) ? "fresh" : undefined}>
                <Link to={linkWith("/search", filters, { q: addTerm(filters.q, "event_type", e.event_type) })}>
                  <span className="time num">{fmtTime(e["@timestamp"])}</span>
                  <span className="swatch" style={{ background: sourceColor(e.source) }} aria-label={sourceLabel(e.source)} />
                  <span className="line">{summarize(e)}</span>
                  <span className="meta">
                    {sourceLabel(e.source)}, {e.tenant}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </aside>
      </section>

      <div className="grid grid-3">
        <TopPanel title="Top source IPs" sub="by events" items={s?.top_src_ips ?? []} onPick={(k) => drill("src_ip", k)} />
        <TopPanel title="Top users" sub="by events" items={s?.top_users ?? []} onPick={(k) => drill("user", k)} />
        <TopPanel title="Top event types" sub="by events" items={s?.top_event_types ?? []} onPick={(k) => drill("event_type", k)} withSource />
      </div>

      <div className="grid grid-2" style={{ marginTop: 16 }}>
        <section className="panel" aria-label="Events by source">
          <div className="panel-head">
            <h2>Events by source</h2>
            <span className="sub">click to filter</span>
          </div>
          <div className="panel-body">
            {s && s.by_source.length === 0 && <Empty title="No sources reporting" />}
            <ul className="toplist">
              {sortSources((s?.by_source ?? []).map((r) => r.key)).map((key) => {
                const count = s!.by_source.find((r) => r.key === key)!.count;
                const max = Math.max(1, ...s!.by_source.map((r) => r.count));
                return (
                  <li key={key}>
                    <button type="button" onClick={() => navigate(linkWith("/search", filters, { sources: [key] }))}>
                      <span className="name">
                        <span className="swatch" style={{ background: sourceColor(key) }} aria-hidden="true" />
                        {sourceLabel(key)}
                      </span>
                      <span className="count">{fmtNum(count)}</span>
                      <span className="bar" aria-hidden="true">
                        <i style={{ width: `${(count / max) * 100}%`, background: sourceColor(key) }} />
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          </div>
        </section>

        <div className="stack">
          <section className="panel" aria-label="Severity mix">
            <div className="panel-head">
              <h2>Severity mix</h2>
              <span className="sub">0 to 10, normalized across sources</span>
            </div>
            <div className="panel-body">
              <div className="sevstrip" aria-hidden="true">
                {SEVERITY_BANDS.map((b) => {
                  const n = sevCounts.get(b.key) ?? 0;
                  return n ? <i key={b.key} style={{ width: `${(n / Math.max(1, sevTotal)) * 100}%`, background: b.color }} /> : null;
                })}
              </div>
              <div className="sevlegend">
                {SEVERITY_BANDS.map((b) => (
                  <div key={b.key}>
                    <span className="row" style={{ gap: 6 }}>
                      <span className="swatch" style={{ background: b.color }} aria-hidden="true" />
                      {b.label}
                    </span>
                    <button
                      type="button"
                      className="btn-ghost"
                      style={{ border: 0, padding: 0, background: "none", cursor: "pointer", textAlign: "left" }}
                      onClick={() => search(`${filters.q} ${b.q}`)}
                    >
                      <strong className="num">{fmtNum(sevCounts.get(b.key) ?? 0)}</strong>
                    </button>
                  </div>
                ))}
              </div>
              <p className="muted" style={{ marginTop: 14, fontSize: 12.5 }}>
                {s ? `Computed in ${s.took_ms} ms, ${s.bucket} buckets.` : "Loading…"}
              </p>
            </div>
          </section>
          <section className="panel" aria-label="Recent alerts">
            <div className="panel-head">
              <h2>Recent alerts</h2>
              <Link to="/alerts" className="sub">
                All alerts
              </Link>
            </div>
            <div className="panel-body">
              {recentAlerts.data && recentAlerts.data.alerts.length === 0 && (
                <Empty title="No alerts">Rules are checked every 15 seconds.</Empty>
              )}
              <ul className="mini-alerts">
                {(recentAlerts.data?.alerts ?? []).map((a) => (
                  <li key={a.id} className={`sev-${severityLevel(a.severity)}`}>
                    <Link to={`/alerts?focus=${a.id}`}>
                      <span className="rail" aria-hidden="true" />
                      <span className="what">
                        <strong>{a.rule_name}</strong>
                        <span className="ink-2">
                          {a.tenant}
                          {a.group_key ? `, ${a.group_key}` : ""}, {a.event_count} events
                        </span>
                      </span>
                      <span className="when">
                        <Severity value={a.severity} label={false} />
                        <span className="muted">{relative(a.created_at)}</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          </section>
        </div>
      </div>
    </>
  );
}
