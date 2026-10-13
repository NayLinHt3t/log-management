import { useEffect, useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, ApiError, type Alert, type Rule } from "../api";
import { useUser } from "../auth";
import { linkWith, readFilters } from "../filters";
import { fmtFull, fmtNum, relative, severityLevel } from "../format";
import { useLoader } from "../hooks";
import { useAppData } from "../components/Layout";
import { IconPlus } from "../components/Icons";
import { Drawer, Empty, ErrorBanner, Severity, useToast } from "../components/ui";

type Status = "open" | "acknowledged" | "closed" | "all";

const GROUP_LABEL: Record<string, string> = {
  src_ip: "source IP",
  dst_ip: "destination IP",
  username: "user",
  host: "host",
  event_type: "event type",
};

/** The search that shows the events behind an alert, over its active window. */
function alertSearchLink(a: Alert) {
  const pad = 60_000;
  return linkWith("/search", readFilters(new URLSearchParams()), {
    range: "custom",
    from: new Date(new Date(a.first_seen).getTime() - pad * 5).toISOString(),
    to: new Date(new Date(a.last_seen).getTime() + pad).toISOString(),
    tenant: a.tenant,
    q: a.query ?? "",
  });
}

function AlertList() {
  const user = useUser();
  const { tenants, refreshAlerts } = useAppData();
  const toast = useToast();
  const [params] = useSearchParams();
  const focus = params.get("focus");
  const [status, setStatus] = useState<Status>(focus ? "all" : "open");
  const [tenant, setTenant] = useState("");
  const { data, error, reload } = useLoader(
    (signal) =>
      api<{ alerts: Alert[]; counts: Record<string, number> }>("/alerts", {
        query: { status, tenant: tenant || undefined, limit: 200 },
        signal,
      }),
    [status, tenant],
    10_000,
  );

  useEffect(() => {
    if (focus && data) document.getElementById(`alert-${focus}`)?.scrollIntoView({ block: "center" });
  }, [focus, data]);

  const act = async (a: Alert, action: "ack" | "close") => {
    try {
      await api(`/alerts/${a.id}/${action}`, { method: "POST" });
      toast({ kind: "success", title: action === "ack" ? "Alert acknowledged" : "Alert closed" });
      void reload();
      refreshAlerts();
    } catch (err) {
      toast({ kind: "error", title: "Could not update the alert", body: (err as Error).message });
    }
  };

  const counts = data?.counts ?? { open: 0, acknowledged: 0, closed: 0 };
  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <div className="segmented" role="group" aria-label="Alert status">
          {(["open", "acknowledged", "closed", "all"] as Status[]).map((s) => (
            <button type="button" key={s} aria-pressed={status === s} onClick={() => setStatus(s)}>
              {s === "all" ? "All" : `${s[0].toUpperCase()}${s.slice(1)} (${counts[s] ?? 0})`}
            </button>
          ))}
        </div>
        {!user.tenant && (
          <select className="select" aria-label="Tenant" value={tenant} onChange={(e) => setTenant(e.target.value)}>
            <option value="">All tenants</option>
            {tenants.map((t) => (
              <option key={t.id} value={t.id}>
                {t.id}
              </option>
            ))}
          </select>
        )}
        <span className="spacer" />
        <span className="muted" style={{ fontSize: 13 }}>
          Rules are evaluated every 15 seconds. New alerts also go to the rule's webhook.
        </span>
      </div>
      <ErrorBanner error={error} />
      <section className="panel">
        {data && data.alerts.length === 0 ? (
          <Empty title={status === "open" ? "No open alerts" : "No alerts"}>
            Alerts appear here when a rule matches. Try the brute-force demo on the{" "}
            <Link to="/sources">Sources</Link> page.
          </Empty>
        ) : (
          <ul className="alert-list">
            {(data?.alerts ?? []).map((a) => (
              <li
                key={a.id}
                id={`alert-${a.id}`}
                className={`alert-item sev-${severityLevel(a.severity)}${focus === a.id ? " focus" : ""}`}
              >
                <span className="rail" aria-hidden="true" />
                <div>
                  <div className="row" style={{ gap: 10 }}>
                    <h3>{a.rule_name}</h3>
                    <span className={`chip status-${a.status}`}>{a.status}</span>
                    <Severity value={a.severity} />
                  </div>
                  <p className="msg">
                    {a.message.startsWith(`${a.rule_name}: `) ? a.message.slice(a.rule_name.length + 2) : a.message}
                  </p>
                  <div className="alert-meta">
                    <span>
                      Tenant <b>{a.tenant}</b>
                    </span>
                    {a.group_key && (
                      <span>
                        {GROUP_LABEL[a.group_by ?? ""] ?? a.group_by} <b>{a.group_key}</b>
                      </span>
                    )}
                    <span>
                      Events <b className="num">{fmtNum(a.event_count)}</b>
                    </span>
                    <span title={fmtFull(a.first_seen)}>
                      First <b>{relative(a.first_seen)}</b>
                    </span>
                    <span title={fmtFull(a.last_seen)}>
                      Last <b>{relative(a.last_seen)}</b>
                    </span>
                    <span>
                      Notification <b>{a.notify_status ?? "pending"}</b>
                    </span>
                    {a.acknowledged_by && (
                      <span>
                        {a.status === "closed" ? "Closed" : "Acknowledged"} by <b>{a.acknowledged_by}</b>
                      </span>
                    )}
                  </div>
                </div>
                <div className="alert-actions">
                  <Link className="btn btn-sm" to={alertSearchLink(a)}>
                    View events
                  </Link>
                  {user.role === "admin" && a.status === "open" && (
                    <button type="button" className="btn btn-sm" onClick={() => act(a, "ack")}>
                      Acknowledge
                    </button>
                  )}
                  {user.role === "admin" && a.status !== "closed" && (
                    <button type="button" className="btn btn-sm btn-ghost" onClick={() => act(a, "close")}>
                      Close
                    </button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  );
}

type RuleForm = {
  name: string;
  description: string;
  tenant: string; // "" = all tenants
  query: string;
  group_by: string; // "" = none
  threshold: number;
  window_minutes: number;
  severity: number;
  webhook_url: string;
  enabled: boolean;
};

const EMPTY_RULE: RuleForm = {
  name: "",
  description: "",
  tenant: "",
  query: "action:login outcome:failure",
  group_by: "src_ip",
  threshold: 3,
  window_minutes: 5,
  severity: 7,
  webhook_url: "",
  enabled: true,
};

function RuleEditor({ rule, onClose, onSaved }: { rule: Rule | null; onClose: () => void; onSaved: () => void }) {
  const user = useUser();
  const { tenants } = useAppData();
  const [form, setForm] = useState<RuleForm>(() =>
    rule
      ? {
          name: rule.name,
          description: rule.description ?? "",
          tenant: rule.tenant ?? "",
          query: rule.query,
          group_by: rule.group_by ?? "",
          threshold: rule.threshold,
          window_minutes: rule.window_minutes,
          severity: rule.severity,
          webhook_url: rule.webhook_url ?? "",
          enabled: rule.enabled,
        }
      : { ...EMPTY_RULE, tenant: user.tenant ?? "" },
  );
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [test, setTest] = useState<string | null>(null);
  const set = <K extends keyof RuleForm>(k: K, v: RuleForm[K]) => setForm((f) => ({ ...f, [k]: v }));

  const body = () => ({
    ...form,
    tenant: form.tenant || null,
    group_by: form.group_by || null,
    description: form.description || null,
    webhook_url: form.webhook_url || null,
  });

  const runTest = async () => {
    setTest("Testing…");
    try {
      const r = await api<{ would_fire: boolean; hits: { tenant: string; group_key: string | null; count: number }[] }>(
        "/alert-rules/test",
        { body: body() },
      );
      setTest(
        r.would_fire
          ? `Would fire now for ${r.hits.length} group${r.hits.length === 1 ? "" : "s"}: ` +
              r.hits
                .slice(0, 5)
                .map((h) => `${h.group_key ?? h.tenant} (${h.count} events)`)
                .join(", ")
          : "Would not fire right now: no group reaches the threshold in the window.",
      );
    } catch (err) {
      setTest(err instanceof ApiError ? `Query problem: ${err.message}` : (err as Error).message);
    }
  };

  const save = async (e: FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    try {
      if (rule) await api(`/alert-rules/${rule.id}`, { method: "PUT", body: body() });
      else await api("/alert-rules", { body: body() });
      onSaved();
    } catch (err) {
      setError(err instanceof ApiError && err.details ? `${err.message}: ${err.details.join("; ")}` : (err as Error).message);
    } finally {
      setSaving(false);
    }
  };

  return (
    <Drawer
      title={rule ? "Edit alert rule" : "New alert rule"}
      onClose={onClose}
      footer={
        <>
          <button type="button" className="btn" onClick={runTest}>
            Test rule
          </button>
          <span className="spacer" />
          <button type="button" className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <button type="submit" form="rule-form" className="btn btn-primary" disabled={saving}>
            {rule ? "Save rule" : "Create rule"}
          </button>
        </>
      }
    >
      <form id="rule-form" onSubmit={save} className="stack">
        <div className="field">
          <label htmlFor="r-name">Name</label>
          <input id="r-name" className="input" required maxLength={120} value={form.name} onChange={(e) => set("name", e.target.value)} placeholder="Repeated failed logins from one IP" />
        </div>
        <div className="field">
          <label htmlFor="r-query">Match events where</label>
          <textarea id="r-query" className="textarea mono" rows={2} value={form.query} onChange={(e) => set("query", e.target.value)} spellCheck={false} />
          <span className="hint">Same syntax as the search box. Leave empty to count every event.</span>
        </div>
        <div className="grid grid-3" style={{ gap: 12 }}>
          <div className="field">
            <label htmlFor="r-threshold">At least</label>
            <input id="r-threshold" className="input" type="number" min={1} value={form.threshold} onChange={(e) => set("threshold", Number(e.target.value))} />
            <span className="hint">events</span>
          </div>
          <div className="field">
            <label htmlFor="r-group">From the same</label>
            <select id="r-group" className="select" value={form.group_by} onChange={(e) => set("group_by", e.target.value)}>
              <option value="">(any, whole tenant)</option>
              {Object.entries(GROUP_LABEL).map(([k, v]) => (
                <option key={k} value={k}>
                  {v}
                </option>
              ))}
            </select>
          </div>
          <div className="field">
            <label htmlFor="r-window">Within</label>
            <input id="r-window" className="input" type="number" min={1} max={1440} value={form.window_minutes} onChange={(e) => set("window_minutes", Number(e.target.value))} />
            <span className="hint">minutes</span>
          </div>
        </div>
        <div className="grid grid-2" style={{ gap: 12 }}>
          <div className="field">
            <label htmlFor="r-sev">Alert severity</label>
            <input id="r-sev" className="input" type="number" min={0} max={10} value={form.severity} onChange={(e) => set("severity", Number(e.target.value))} />
            <span className="hint">0 to 10</span>
          </div>
          <div className="field">
            <label htmlFor="r-tenant">Applies to</label>
            {user.tenant ? (
              <input id="r-tenant" className="input" value={`Tenant ${user.tenant}`} disabled />
            ) : (
              <select id="r-tenant" className="select" value={form.tenant} onChange={(e) => set("tenant", e.target.value)}>
                <option value="">All tenants</option>
                {tenants.map((t) => (
                  <option key={t.id} value={t.id}>
                    Tenant {t.id}
                  </option>
                ))}
              </select>
            )}
          </div>
        </div>
        <div className="field">
          <label htmlFor="r-hook">Webhook URL (optional)</label>
          <input id="r-hook" className="input" type="url" value={form.webhook_url} onChange={(e) => set("webhook_url", e.target.value)} placeholder="https://hooks.slack.com/… or https://webhook.site/…" />
          <span className="hint">A JSON POST is sent when an alert opens. Without one, alerts show in this page only (or go to ALERT_WEBHOOK_URL).</span>
        </div>
        <div className="field">
          <label htmlFor="r-desc">Description (optional)</label>
          <input id="r-desc" className="input" value={form.description} onChange={(e) => set("description", e.target.value)} />
        </div>
        <label className="check">
          <input type="checkbox" checked={form.enabled} onChange={(e) => set("enabled", e.target.checked)} />
          Enabled
        </label>
        {test && <div className="banner">{test}</div>}
        <ErrorBanner error={error} />
      </form>
    </Drawer>
  );
}

function RuleList() {
  const user = useUser();
  const toast = useToast();
  const [editing, setEditing] = useState<Rule | "new" | null>(null);
  const { data, error, reload } = useLoader((signal) => api<{ rules: Rule[] }>("/alert-rules", { signal }), []);

  const canEdit = (r: Rule) => user.role === "admin" && (user.tenant === null || r.tenant === user.tenant);
  const toggle = async (r: Rule) => {
    try {
      await api(`/alert-rules/${r.id}`, { method: "PATCH", body: { enabled: !r.enabled } });
      void reload();
    } catch (err) {
      toast({ kind: "error", title: "Could not update the rule", body: (err as Error).message });
    }
  };
  const remove = async (r: Rule) => {
    if (!window.confirm(`Delete the rule "${r.name}"? Its past alerts are kept.`)) return;
    try {
      await api(`/alert-rules/${r.id}`, { method: "DELETE" });
      toast({ kind: "success", title: "Rule deleted" });
      void reload();
    } catch (err) {
      toast({ kind: "error", title: "Could not delete the rule", body: (err as Error).message });
    }
  };

  return (
    <>
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="muted">
          A rule fires when matching events reach the threshold inside the time window, counted per group.
        </span>
        <span className="spacer" />
        {user.role === "admin" && (
          <button type="button" className="btn btn-primary" onClick={() => setEditing("new")}>
            <IconPlus /> New rule
          </button>
        )}
      </div>
      <ErrorBanner error={error} />
      <section className="panel">
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>On</th>
                <th>Rule</th>
                <th>Condition</th>
                <th>Applies to</th>
                <th>Severity</th>
                <th>Notifies</th>
                <th>Open alerts</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(data?.rules ?? []).map((r) => (
                <tr key={r.id}>
                  <td>
                    <input
                      type="checkbox"
                      aria-label={`${r.enabled ? "Disable" : "Enable"} ${r.name}`}
                      checked={r.enabled}
                      disabled={!canEdit(r)}
                      onChange={() => toggle(r)}
                      style={{ width: 16, height: 16, accentColor: "var(--ink)" }}
                    />
                  </td>
                  <td style={{ maxWidth: 340 }}>
                    <strong>{r.name}</strong>
                    {r.description && <span className="event-sub" style={{ whiteSpace: "normal" }}>{r.description}</span>}
                  </td>
                  <td className="condition">
                    <code>{r.query || "(every event)"}</code>
                    <div>
                      {r.threshold}+ events{r.group_by ? ` from one ${GROUP_LABEL[r.group_by] ?? r.group_by}` : ""} in {r.window_minutes} min
                    </div>
                  </td>
                  <td>{r.tenant ? `Tenant ${r.tenant}` : "All tenants"}</td>
                  <td>
                    <Severity value={r.severity} />
                  </td>
                  <td>{r.webhook_url ? "Webhook + UI" : "UI"}</td>
                  <td className="num">{fmtNum(r.open_alerts ?? 0)}</td>
                  <td className="nowrap">
                    {canEdit(r) && (
                      <>
                        <button type="button" className="btn btn-sm btn-ghost" onClick={() => setEditing(r)}>
                          Edit
                        </button>
                        <button type="button" className="btn btn-sm btn-ghost btn-danger" onClick={() => remove(r)}>
                          Delete
                        </button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data && data.rules.length === 0 && <Empty title="No rules yet">Create one to start alerting.</Empty>}
      </section>
      {editing && (
        <RuleEditor
          rule={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={() => {
            toast({ kind: "success", title: editing === "new" ? "Rule created" : "Rule saved" });
            setEditing(null);
            void reload();
          }}
        />
      )}
    </>
  );
}

export function Alerts() {
  const [params, setParams] = useSearchParams();
  const tab = params.get("tab") === "rules" ? "rules" : "alerts";
  const { openAlerts } = useAppData();
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p>Detections raised by alert rules across your tenants.</p>
        </div>
      </div>
      <div className="tabs" role="tablist">
        <button type="button" role="tab" aria-selected={tab === "alerts"} onClick={() => setParams({})}>
          Alerts{openAlerts ? ` (${openAlerts} open)` : ""}
        </button>
        <button type="button" role="tab" aria-selected={tab === "rules"} onClick={() => setParams({ tab: "rules" })}>
          Rules
        </button>
      </div>
      {tab === "alerts" ? <AlertList /> : <RuleList />}
    </>
  );
}
