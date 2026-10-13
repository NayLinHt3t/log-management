import { createContext, useContext, useEffect, useRef } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api, type Alert, type Tenant } from "../api";
import { useAuth, useUser } from "../auth";
import { useLoader, usePref } from "../hooks";
import { BrandMark, IconLogout, IconMoon, IconSun } from "./Icons";
import { useToast } from "./ui";

interface AppData {
  tenants: Tenant[];
  openAlerts: number;
  reloadTenants: () => void;
  refreshAlerts: () => void;
}

const AppDataCtx = createContext<AppData>({
  tenants: [],
  openAlerts: 0,
  reloadTenants: () => undefined,
  refreshAlerts: () => undefined,
});
// eslint-disable-next-line react-refresh/only-export-components
export const useAppData = () => useContext(AppDataCtx);

type Theme = "system" | "light" | "dark";

function ThemeToggle() {
  const [theme, setTheme] = usePref<Theme>("logmgmt.theme", "system");
  useEffect(() => {
    const root = document.documentElement;
    if (theme === "system") delete root.dataset.theme;
    else root.dataset.theme = theme;
  }, [theme]);
  const next: Theme = theme === "system" ? "light" : theme === "light" ? "dark" : "system";
  const dark =
    theme === "dark" || (theme === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
  return (
    <button
      className="btn btn-ghost icon-btn"
      onClick={() => setTheme(next)}
      title={`Theme: ${theme} (switch to ${next})`}
      aria-label={`Theme: ${theme}. Switch to ${next}`}
    >
      {dark ? <IconMoon /> : <IconSun />}
    </button>
  );
}

export function Layout() {
  const user = useUser();
  const { logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const toast = useToast();

  const tenants = useLoader((signal) => api<{ tenants: Tenant[] }>("/tenants", { signal }), []);
  const alerts = useLoader(
    (signal) => api<{ alerts: Alert[]; counts: Record<string, number> }>("/alerts", { query: { status: "open", limit: 20 }, signal }),
    [],
    10_000,
  );

  // Toast for alerts that appeared since the last poll (not for the ones already open at login).
  const lastSeen = useRef<number | null>(null);
  useEffect(() => {
    if (!alerts.data) return;
    const ids = alerts.data.alerts.map((a) => Number(a.id));
    const maxId = ids.length ? Math.max(...ids) : 0;
    if (lastSeen.current === null) {
      lastSeen.current = maxId;
      return;
    }
    const fresh = alerts.data.alerts.filter((a) => Number(a.id) > (lastSeen.current ?? 0));
    for (const a of fresh.slice(0, 3)) {
      toast({
        kind: "alert",
        title: a.rule_name,
        body: `${a.tenant}: ${a.event_count} events${a.group_key ? ` from ${a.group_key}` : ""}`,
        action: { label: "Open alert", onClick: () => navigate(`/alerts?focus=${a.id}`) },
      });
    }
    lastSeen.current = Math.max(lastSeen.current, maxId);
  }, [alerts.data, toast, navigate]);

  const openAlerts = alerts.data?.counts.open ?? 0;
  // Dashboard and Search share filters, so moving between them keeps the current slice.
  const carry = location.pathname === "/" || location.pathname === "/search" ? location.search : "";

  return (
    <AppDataCtx.Provider
      value={{
        tenants: tenants.data?.tenants ?? [],
        openAlerts,
        reloadTenants: tenants.reload,
        refreshAlerts: alerts.reload,
      }}
    >
      <header className="topbar">
        <NavLink to="/" className="brand" aria-label="Log Management home">
          <BrandMark />
          <span>Log Management</span>
        </NavLink>
        <nav className="nav" aria-label="Main">
          <NavLink to={`/${carry}`} end>
            Dashboard
          </NavLink>
          <NavLink to={`/search${carry}`}>Search</NavLink>
          <NavLink to="/alerts">
            Alerts
            {openAlerts > 0 && (
              <span className="count-badge" aria-label={`${openAlerts} open`}>
                {openAlerts}
              </span>
            )}
          </NavLink>
          <NavLink to="/sources">Sources</NavLink>
          {user.role === "admin" && <NavLink to="/admin">Admin</NavLink>}
        </nav>
        <div className="topbar-right">
          <div className="identity">
            <strong>{user.username}</strong>
            <span>
              {user.role === "admin" ? "Admin" : "Viewer"}, {user.tenant ? `tenant ${user.tenant}` : "all tenants"}
            </span>
          </div>
          <ThemeToggle />
          <button className="btn btn-ghost icon-btn" onClick={logout} title="Log out" aria-label="Log out">
            <IconLogout />
          </button>
        </div>
      </header>
      <main>
        <Outlet />
      </main>
    </AppDataCtx.Provider>
  );
}
