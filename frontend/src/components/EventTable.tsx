import { Fragment, useState, type KeyboardEvent } from "react";
import type { EventRow } from "../api";
import { fmtFull, fmtWhen } from "../format";
import { CopyBlock, Severity, SourceName } from "./ui";

type AddTerm = (field: string, value: string) => void;

export function Flow({ e }: { e: EventRow }) {
  if (!e.src_ip && !e.dst_ip) return <span className="muted">–</span>;
  const end = (ip?: string, port?: number) => (ip ? `${ip}${port !== undefined ? `:${port}` : ""}` : "?");
  return (
    <span className="flow">
      {end(e.src_ip, e.src_port)}
      {e.dst_ip && (
        <>
          <span className="arrow" aria-label="to">
            →
          </span>
          {end(e.dst_ip, e.dst_port)}
        </>
      )}
    </span>
  );
}

// normalized field -> [label, query field]
const DETAIL_FIELDS: [keyof EventRow | string, string, string][] = [
  ["@timestamp", "Time", ""],
  ["tenant", "Tenant", "tenant"],
  ["source", "Source", "source"],
  ["vendor", "Vendor", "vendor"],
  ["product", "Product", "product"],
  ["event_type", "Event type", "event_type"],
  ["event_subtype", "Detail", "event_subtype"],
  ["severity", "Severity", "severity"],
  ["action", "Action", "action"],
  ["outcome", "Outcome", "outcome"],
  ["user", "User", "user"],
  ["src_ip", "Source IP", "src_ip"],
  ["src_port", "Source port", "src_port"],
  ["dst_ip", "Destination IP", "dst_ip"],
  ["dst_port", "Destination port", "dst_port"],
  ["protocol", "Protocol", "protocol"],
  ["host", "Host", "host"],
  ["process", "Process", "process"],
  ["url", "URL", "url"],
  ["http_method", "HTTP method", "method"],
  ["status_code", "Status code", "status"],
  ["rule_name", "Rule", "rule"],
  ["rule_id", "Rule id", "rule_id"],
  ["cloud.account_id", "Cloud account", "account"],
  ["cloud.region", "Cloud region", "region"],
  ["cloud.service", "Cloud service", "service"],
  ["ingested_at", "Received", ""],
];

const get = (e: EventRow, path: string): unknown =>
  path.split(".").reduce<unknown>((o, k) => (o && typeof o === "object" ? (o as Record<string, unknown>)[k] : undefined), e);

export function EventDetail({ e, onAddTerm }: { e: EventRow; onAddTerm?: AddTerm }) {
  const rows = DETAIL_FIELDS.map(([path, label, field]) => [label, field, get(e, path as string)] as const).filter(
    ([, , v]) => v !== undefined && v !== null && v !== "",
  );
  return (
    <div className="detail">
      <div>
        <h3 style={{ marginBottom: 8 }}>Normalized fields</h3>
        <dl>
          {rows.map(([label, field, value]) => (
            <Fragment key={label}>
              <dt>{label}</dt>
              <dd>
                {label === "Time" || label === "Received" ? (
                  fmtFull(String(value))
                ) : onAddTerm && field ? (
                  <button type="button" title={`Add ${field}:${String(value)} to the search`} onClick={() => onAddTerm(field, String(value))}>
                    {String(value)}
                  </button>
                ) : (
                  String(value)
                )}
              </dd>
            </Fragment>
          ))}
          {e._tags.length > 0 && (
            <>
              <dt>Tags</dt>
              <dd>
                {e._tags.map((t) =>
                  onAddTerm ? (
                    <button key={t} type="button" className="tag" onClick={() => onAddTerm("tag", t)} style={{ textDecoration: "none" }}>
                      {t}
                    </button>
                  ) : (
                    <span key={t} className="tag">
                      {t}
                    </span>
                  ),
                )}
              </dd>
            </>
          )}
        </dl>
      </div>
      <div>
        <h3 style={{ marginBottom: 8 }}>Original record</h3>
        <CopyBlock code={JSON.stringify(e.raw, null, 2)} />
      </div>
    </div>
  );
}

export function EventTable({ events, onAddTerm, showTenant = true }: { events: EventRow[]; onAddTerm?: AddTerm; showTenant?: boolean }) {
  const [open, setOpen] = useState<string | null>(null);
  const toggle = (id: string) => setOpen((cur) => (cur === id ? null : id));
  const onKey = (ev: KeyboardEvent, id: string) => {
    if (ev.key === "Enter" || ev.key === " ") {
      ev.preventDefault();
      toggle(id);
    }
  };
  const cols = showTenant ? 8 : 7;
  return (
    <div className="table-wrap">
      <table className="table">
        <thead>
          <tr>
            <th>Time</th>
            {showTenant && <th>Tenant</th>}
            <th>Source</th>
            <th>Event</th>
            <th>Severity</th>
            <th>User</th>
            <th>Source → destination</th>
            <th>Host</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e) => (
            <Fragment key={e.id}>
              <tr
                className={`clickable${open === e.id ? " expanded" : ""}`}
                tabIndex={0}
                aria-expanded={open === e.id}
                onClick={() => toggle(e.id)}
                onKeyDown={(ev) => onKey(ev, e.id)}
              >
                <td className="nowrap num" title={fmtFull(e["@timestamp"])}>
                  {fmtWhen(e["@timestamp"])}
                </td>
                {showTenant && <td>{e.tenant}</td>}
                <td className="nowrap">
                  <SourceName source={e.source} />
                </td>
                <td>
                  <span className="event-name">{e.event_type}</span>
                  {e.event_subtype && <span className="event-sub">{e.event_subtype}</span>}
                </td>
                <td>
                  <Severity value={e.severity} label={false} />
                </td>
                <td>{e.user ?? <span className="muted">–</span>}</td>
                <td>
                  <Flow e={e} />
                </td>
                <td>{e.host ?? <span className="muted">–</span>}</td>
              </tr>
              {open === e.id && (
                <tr className="expanded">
                  <td colSpan={cols}>
                    <EventDetail e={e} onAddTerm={onAddTerm} />
                  </td>
                </tr>
              )}
            </Fragment>
          ))}
        </tbody>
      </table>
    </div>
  );
}
