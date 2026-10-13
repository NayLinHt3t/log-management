import { useRef, useState, type FormEvent } from "react";
import { api, type ApiKey, type IngestResult, type SystemStatus } from "../api";
import { useUser } from "../auth";
import { fmtFull, fmtNum, relative } from "../format";
import { useLoader } from "../hooks";
import { SOURCES, sourceLabel } from "../sources";
import { useAppData } from "../components/Layout";
import { CopyBlock, Empty, ErrorBanner, useToast } from "../components/ui";

const host = typeof window !== "undefined" ? window.location.hostname : "localhost";
const origin = typeof window !== "undefined" ? window.location.origin : "https://localhost";
const selfSigned = origin.startsWith("https://") && /^(localhost|\d+\.\d+\.\d+\.\d+)$/.test(host);

const SERVICE_LABEL: Record<string, string> = {
  backend: "API (backend)",
  ingest: "Syslog + inbox collector (ingest)",
  worker: "Alerts + retention (worker)",
};

const STAT_LABEL: Record<string, string> = {
  syslog_udp_messages: "UDP messages",
  syslog_tcp_messages: "TCP messages",
  events_accepted: "events accepted",
  events_rejected: "rejected",
  events_buffered: "buffered",
  files_processed: "files processed",
  files_failed: "files failed",
  http_requests: "HTTP requests",
  ingest_events: "API events",
  alert_evaluations: "rule evaluations",
  alerts_created: "alerts created",
  notifications_sent: "webhooks sent",
  notifications_failed: "webhooks failed",
  partitions_dropped: "partitions dropped",
};

function Health() {
  const { data, error } = useLoader((signal) => api<SystemStatus>("/system/status", { signal }), [], 10_000);
  return (
    <section className="panel" aria-label="Pipeline health">
      <div className="panel-head">
        <h2>Pipeline health</h2>
        <span className="sub">heartbeats every 10 s</span>
      </div>
      <div className="panel-body">
        <ErrorBanner error={error} />
        {(data?.services ?? []).map((s) => (
          <div className="service" key={s.service}>
            <span className={`dot${s.healthy ? "" : " down"}`} aria-hidden="true" />
            <div>
              <strong>{SERVICE_LABEL[s.service] ?? s.service}</strong>{" "}
              <span className={s.healthy ? "muted" : ""} style={s.healthy ? undefined : { color: "var(--critical-text)" }}>
                {s.healthy ? "running" : "not reporting"}, last heartbeat {relative(s.last_seen)}
              </span>
            </div>
            <dl>
              {Object.entries(s.stats)
                .filter(([k, v]) => STAT_LABEL[k] && typeof v === "number")
                .map(([k, v]) => (
                  <div key={k}>
                    <dt>{STAT_LABEL[k]}</dt>
                    <dd>{fmtNum(v as number)}</dd>
                  </div>
                ))}
              {typeof s.stats.last_event_at === "string" && (
                <div>
                  <dt>last syslog event</dt>
                  <dd>{relative(s.stats.last_event_at)}</dd>
                </div>
              )}
            </dl>
          </div>
        ))}
        {data && data.services.length === 0 && <Empty title="No services have reported yet" />}
        {data && (
          <p className="muted" style={{ marginTop: 12, fontSize: 13 }}>
            Retention keeps {data.retention_days} days of events per tenant (whole daily partitions are dropped).
            {data.partitions.length > 0 &&
              ` Oldest stored day: ${data.partitions.map((p) => `${p.tenant} ${p.oldest_day.slice(0, 10)}`).join(", ")}.`}
          </p>
        )}
      </div>
    </section>
  );
}

function Upload() {
  const user = useUser();
  const { tenants } = useAppData();
  const toast = useToast();
  const fileRef = useRef<HTMLInputElement>(null);
  const [tenant, setTenant] = useState(user.tenant ?? "");
  const [source, setSource] = useState("");
  const [result, setResult] = useState<IngestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (user.role !== "admin") {
    return (
      <p className="muted">Uploading files needs the admin role. Viewers can search and view everything in their tenant.</p>
    );
  }

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const file = fileRef.current?.files?.[0];
    if (!file) {
      setError("Choose a file first.");
      return;
    }
    const form = new FormData();
    if (tenant) form.append("tenant", tenant);
    if (source) form.append("source", source);
    form.append("file", file);
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      const r = await api<IngestResult>("/ingest/file", { form });
      setResult(r);
      toast({ kind: "success", title: `Imported ${fmtNum(r.accepted)} events`, body: file.name });
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <form onSubmit={submit} className="stack" style={{ gap: 12 }}>
      <div className="grid grid-3" style={{ gap: 12 }}>
        <div className="field">
          <label htmlFor="u-tenant">Tenant</label>
          {user.tenant ? (
            <input id="u-tenant" className="input" value={user.tenant} disabled />
          ) : (
            <select id="u-tenant" className="select" value={tenant} onChange={(e) => setTenant(e.target.value)}>
              <option value="">From each record</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id}
                </option>
              ))}
            </select>
          )}
        </div>
        <div className="field">
          <label htmlFor="u-source">Source</label>
          <select id="u-source" className="select" value={source} onChange={(e) => setSource(e.target.value)}>
            <option value="">Detect automatically</option>
            {SOURCES.map((s) => (
              <option key={s} value={s}>
                {sourceLabel(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="u-file">File</label>
          <input id="u-file" ref={fileRef} className="input" type="file" accept=".json,.ndjson,.jsonl,.csv,.log,.txt" style={{ paddingTop: 5 }} />
        </div>
      </div>
      <div className="row">
        <button className="btn btn-primary" type="submit" disabled={busy}>
          {busy ? "Importing…" : "Import file"}
        </button>
        <span className="muted" style={{ fontSize: 13 }}>
          JSON array, CloudTrail <code>{"{Records: [...]}"}</code>, NDJSON, CSV with a header row, or syslog lines (.log).
        </span>
      </div>
      <ErrorBanner error={error} />
      {result && (
        <div className={`banner ${result.accepted ? "success" : "error"}`}>
          <strong>
            {fmtNum(result.accepted)} imported, {fmtNum(result.rejected)} rejected
          </strong>
          {result.format && <span className="muted"> (read as {result.format})</span>}
          {result.restamped > 0 && (
            <p className="ink-2" style={{ marginTop: 4 }}>
              {fmtNum(result.restamped)} records were older than the retention window and were stamped with the
              arrival time (tag <code>ts_restamped</code>; the original time stays in the raw record).
            </p>
          )}
          {result.errors.length > 0 && (
            <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
              {result.errors.slice(0, 8).map((e, i) => (
                <li key={i}>{e.error}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </form>
  );
}

function ApiKeys() {
  const user = useUser();
  const { tenants } = useAppData();
  const toast = useToast();
  const { data, error, reload } = useLoader((signal) => api<{ keys: ApiKey[] }>("/api-keys", { signal }), []);
  const [name, setName] = useState("");
  const [tenant, setTenant] = useState(user.tenant ?? "");
  const [created, setCreated] = useState<ApiKey | null>(null);
  const [formError, setFormError] = useState<string | null>(null);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    try {
      const k = await api<ApiKey>("/api-keys", { body: { name, tenant: tenant || null } });
      setCreated(k);
      setName("");
      void reload();
    } catch (err) {
      setFormError((err as Error).message);
    }
  };
  const revoke = async (k: ApiKey) => {
    if (!window.confirm(`Revoke "${k.name}"? Senders using it will get 401 errors.`)) return;
    try {
      await api(`/api-keys/${k.id}`, { method: "DELETE" });
      toast({ kind: "success", title: "Key revoked" });
      void reload();
    } catch (err) {
      toast({ kind: "error", title: "Could not revoke the key", body: (err as Error).message });
    }
  };

  return (
    <section className="panel" aria-label="Ingest API keys">
      <div className="panel-head">
        <h2>Ingest API keys</h2>
        <span className="sub">sent as the X-API-Key header</span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <ErrorBanner error={error} />
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Writes to</th>
                <th>Key starts with</th>
                <th>Last used</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(data?.keys ?? []).map((k) => (
                <tr key={k.id} style={k.revoked_at ? { opacity: 0.5 } : undefined}>
                  <td>{k.name}</td>
                  <td>{k.tenant ? `Tenant ${k.tenant} only` : "Any tenant in the payload"}</td>
                  <td className="mono nowrap">{k.key_prefix}…</td>
                  <td title={fmtFull(k.last_used_at)}>{k.revoked_at ? "revoked" : relative(k.last_used_at)}</td>
                  <td>
                    {!k.revoked_at && (
                      <button type="button" className="btn btn-sm btn-ghost btn-danger" onClick={() => revoke(k)}>
                        Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <form className="row" onSubmit={create}>
          <input className="input" required placeholder="Key name, e.g. demoA web app" value={name} onChange={(e) => setName(e.target.value)} style={{ flex: "1 1 220px" }} />
          {user.tenant ? null : (
            <select className="select" aria-label="Tenant" value={tenant} onChange={(e) => setTenant(e.target.value)}>
              <option value="">Any tenant (trusted collector)</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  Tenant {t.id} only
                </option>
              ))}
            </select>
          )}
          <button className="btn" type="submit">
            Create key
          </button>
        </form>
        <ErrorBanner error={formError} />
        {created?.key && (
          <div className="banner success">
            <p style={{ marginBottom: 8 }}>
              Copy this key now. It is stored only as a hash and will not be shown again.
            </p>
            <CopyBlock code={created.key} />
          </div>
        )}
      </div>
    </section>
  );
}

export function Sources() {
  const user = useUser();
  const { data: status } = useLoader((signal) => api<SystemStatus>("/system/status", { signal }), []);
  const ingest = status?.services.find((s) => s.service === "ingest");
  const defaultTenant = (ingest?.stats.default_tenant as string | undefined) ?? "demoA";
  const k = selfSigned ? "-k " : "";

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Sources</h1>
          <p>
            Four ways to send logs. Whatever the format, every record is normalized into one schema (time, tenant,
            source, event type, severity, user, IPs, host…) before it is stored.
          </p>
        </div>
      </div>

      <div className="grid grid-2">
        <section className="panel method">
          <div className="panel-body">
            <h3>Syslog, UDP or TCP port 514</h3>
            <p>
              Firewalls, routers and Linux hosts. RFC 3164, RFC 5424, CEF and key=value payloads are understood.
              Messages go to tenant <b>{defaultTenant}</b> unless the sender's address is mapped to another tenant.
            </p>
            <CopyBlock
              code={`echo '<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS' | nc -u -w1 ${host} 514\n\nlogger -n ${host} -P 514 -T "hello over TCP"`}
            />
          </div>
        </section>
        <section className="panel method">
          <div className="panel-body">
            <h3>HTTP API, POST /api/ingest</h3>
            <p>
              Applications and cloud connectors. Send one JSON object, an array, NDJSON, or plain-text syslog lines,
              with an ingest API key.
            </p>
            <CopyBlock
              code={`curl ${k}-X POST ${origin}/api/ingest \\\n  -H "X-API-Key: $INGEST_API_KEY" -H "Content-Type: application/json" \\\n  -d '{"tenant":"demoA","source":"api","event_type":"app_login_failed","user":"alice","ip":"203.0.113.7","reason":"wrong_password"}'`}
            />
          </div>
        </section>
        <section className="panel method">
          <div className="panel-body">
            <h3>Files: upload or inbox folder</h3>
            <p>
              Exports from AWS CloudTrail, Microsoft 365 audit, Windows security events or CrowdStrike. Upload below,
              or copy files into the appliance's inbox folder; they are picked up within 5 seconds.
            </p>
            <CopyBlock code={`cp samples/aws_cloudtrail.json data/inbox/demoB/\ncp samples/ad_security_events.csv data/inbox/demoA/`} />
          </div>
        </section>
        <section className="panel method">
          <div className="panel-body">
            <h3>Simulator</h3>
            <p>
              Generates realistic traffic for all seven sources over syslog and HTTP, including a brute-force burst
              that trips the default alert rule.
            </p>
            <CopyBlock code={`python3 samples/simulate.py --url ${origin}${selfSigned ? " --insecure" : ""} --minutes 5\npython3 samples/simulate.py --url ${origin}${selfSigned ? " --insecure" : ""} --scenario bruteforce`} />
          </div>
        </section>
      </div>

      <section className="panel" style={{ marginTop: 16 }}>
        <div className="panel-head">
          <h2>Import a file</h2>
          <span className="sub">{user.role === "admin" ? "parsed, normalized and stored immediately" : "admins only"}</span>
        </div>
        <div className="panel-body">
          <Upload />
        </div>
      </section>

      <div className="grid grid-2" style={{ marginTop: 16, alignItems: "start" }}>
        <Health />
        {user.role === "admin" ? (
          <ApiKeys />
        ) : (
          <section className="panel">
            <div className="panel-body">
              <h3>Ingest API keys</h3>
              <p className="muted" style={{ marginTop: 6 }}>
                Ask an admin for a key bound to tenant {user.tenant}.
              </p>
            </div>
          </section>
        )}
      </div>
    </>
  );
}
