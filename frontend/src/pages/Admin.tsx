import { useState, type FormEvent } from "react";
import { api, ApiError, type Tenant, type UserRow } from "../api";
import { useUser } from "../auth";
import { fmtFull, fmtNum, relative } from "../format";
import { useLoader } from "../hooks";
import { useAppData } from "../components/Layout";
import { ErrorBanner, useToast } from "../components/ui";

const errText = (err: unknown) =>
  err instanceof ApiError && err.details ? `${err.message}: ${err.details.join("; ")}` : (err as Error).message;

function Tenants() {
  const user = useUser();
  const toast = useToast();
  const { reloadTenants } = useAppData();
  const { data, error, reload } = useLoader((signal) => api<{ tenants: Tenant[] }>("/tenants", { signal }), []);
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [retention, setRetention] = useState("");
  const [formError, setFormError] = useState<string | null>(null);
  const global = user.tenant === null;

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    try {
      await api("/tenants", { body: { id, name, retention_days: retention ? Number(retention) : null } });
      toast({ kind: "success", title: `Tenant ${id} created`, body: "Its tables were created; create a viewer or API key next." });
      setId("");
      setName("");
      setRetention("");
      void reload();
      reloadTenants();
    } catch (err) {
      setFormError(errText(err));
    }
  };

  const editRetention = async (t: Tenant) => {
    const v = window.prompt(`Retention for ${t.id} in days (7 or more, empty = default)`, t.retention_days ? String(t.retention_days) : "");
    if (v === null) return;
    try {
      await api(`/tenants/${t.id}`, { method: "PATCH", body: { retention_days: v.trim() ? Number(v) : null } });
      void reload();
    } catch (err) {
      toast({ kind: "error", title: "Could not change retention", body: errText(err) });
    }
  };

  return (
    <section className="panel" aria-label="Tenants">
      <div className="panel-head">
        <h2>Tenants</h2>
        <span className="sub">each tenant has its own tables, partitioned by day</span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <ErrorBanner error={error} />
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Id</th>
                <th>Name</th>
                <th>Retention</th>
                <th>Stored days</th>
                <th>Oldest day</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(data?.tenants ?? []).map((t) => (
                <tr key={t.id}>
                  <td>
                    <strong>{t.id}</strong>
                  </td>
                  <td>{t.name}</td>
                  <td>
                    {t.effective_retention_days} days{t.retention_days ? "" : " (default)"}
                  </td>
                  <td className="num">{fmtNum(t.partitions)}</td>
                  <td>{t.oldest_day ? t.oldest_day.slice(0, 10) : "–"}</td>
                  <td>
                    {global && (
                      <button type="button" className="btn btn-sm btn-ghost" onClick={() => editRetention(t)}>
                        Change retention
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {global && (
          <form className="row" onSubmit={create}>
            <input className="input" required placeholder="Id, e.g. acme" pattern="[A-Za-z0-9][A-Za-z0-9_\-]{0,31}" value={id} onChange={(e) => setId(e.target.value)} style={{ width: 160 }} />
            <input className="input" required placeholder="Display name" value={name} onChange={(e) => setName(e.target.value)} style={{ flex: "1 1 200px" }} />
            <input className="input" type="number" min={7} placeholder="Retention days" value={retention} onChange={(e) => setRetention(e.target.value)} style={{ width: 150 }} />
            <button className="btn" type="submit">
              Create tenant
            </button>
          </form>
        )}
        <ErrorBanner error={formError} />
      </div>
    </section>
  );
}

function Users() {
  const user = useUser();
  const toast = useToast();
  const { tenants } = useAppData();
  const { data, error, reload } = useLoader((signal) => api<{ users: UserRow[] }>("/users", { signal }), []);
  const [form, setForm] = useState({ username: "", password: "", role: "viewer", tenant: user.tenant ?? "" });
  const [formError, setFormError] = useState<string | null>(null);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setFormError(null);
    try {
      await api("/users", { body: { ...form, tenant: form.tenant || null } });
      toast({ kind: "success", title: `User ${form.username} created` });
      setForm({ username: "", password: "", role: "viewer", tenant: user.tenant ?? "" });
      void reload();
    } catch (err) {
      setFormError(errText(err));
    }
  };
  const remove = async (u: UserRow) => {
    if (!window.confirm(`Delete user ${u.username}?`)) return;
    try {
      await api(`/users/${u.id}`, { method: "DELETE" });
      void reload();
    } catch (err) {
      toast({ kind: "error", title: "Could not delete the user", body: errText(err) });
    }
  };

  return (
    <section className="panel" aria-label="Users">
      <div className="panel-head">
        <h2>Users and roles</h2>
        <span className="sub">viewers are read-only and see one tenant</span>
      </div>
      <div className="panel-body stack" style={{ gap: 12 }}>
        <ErrorBanner error={error} />
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>User</th>
                <th>Role</th>
                <th>Tenant</th>
                <th>Last login</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {(data?.users ?? []).map((u) => (
                <tr key={u.id}>
                  <td>
                    <strong>{u.username}</strong>
                  </td>
                  <td>{u.role === "admin" ? "Admin" : "Viewer"}</td>
                  <td>{u.tenant ?? "All tenants"}</td>
                  <td title={fmtFull(u.last_login_at)}>{relative(u.last_login_at)}</td>
                  <td>
                    {u.username !== user.username && (
                      <button type="button" className="btn btn-sm btn-ghost btn-danger" onClick={() => remove(u)}>
                        Delete
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <form className="row" onSubmit={create}>
          <input className="input" required placeholder="Username" autoComplete="off" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} style={{ width: 160 }} />
          <input className="input" required type="password" minLength={8} placeholder="Password (8+ characters)" autoComplete="new-password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} style={{ width: 210 }} />
          <select className="select" aria-label="Role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value })}>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
          {user.tenant ? null : (
            <select className="select" aria-label="Tenant" value={form.tenant} onChange={(e) => setForm({ ...form, tenant: e.target.value })}>
              <option value="">All tenants (admins only)</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id}
                </option>
              ))}
            </select>
          )}
          <button className="btn" type="submit">
            Create user
          </button>
        </form>
        <ErrorBanner error={formError} />
      </div>
    </section>
  );
}

export function Admin() {
  return (
    <>
      <div className="page-head">
        <div>
          <h1>Admin</h1>
          <p>Tenants, retention and who can see what. A user's tenant is part of their login token and every query is filtered by it.</p>
        </div>
      </div>
      <div className="stack">
        <Tenants />
        <Users />
      </div>
    </>
  );
}
