import { useState, type FormEvent } from "react";
import { useAuth } from "../auth";
import { BrandMark } from "../components/Icons";
import { ErrorBanner } from "../components/ui";

// A few lines in the formats the system ingests; the flagged one is what alerting is for.
const LINES = [
  "<134>Aug 20 12:44:56 fw01 action=deny src=10.0.1.10 dst=8.8.8.8 dpt=53 proto=udp",
  '{"source":"aws","eventName":"CreateUser","awsRegion":"ap-southeast-1"}',
  "<190>Aug 20 13:01:02 r1 if=ge-0/0/1 event=link-down reason=carrier-loss",
  '{"source":"ad","event_id":4625,"user":"demo\\\\eve","ip":"203.0.113.77"}',
  '{"source":"m365","Operation":"UserLoggedIn","ClientIP":"198.51.100.23"}',
  "CEF:0|Acme|NGFW|9.1|1001|Port scan detected|7|src=198.51.100.9 dpt=22",
  '{"source":"crowdstrike","event_type":"malware_detected","host":"WIN10-01"}',
];

export function Login() {
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(username, password);
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <aside className="login-side">
        <span className="brand">
          <BrandMark />
          Log Management
        </span>
        <div>
          <h1>Every source, one schema, one place to search.</h1>
          <p className="lede">
            Syslog, HTTP, CloudTrail, Microsoft 365, Windows security and EDR events, normalized per tenant, with
            alerting on top.
          </p>
        </div>
        <div className="login-lines" aria-hidden="true">
          {LINES.map((l, i) => (
            <div key={l} className={i === 3 ? "hl" : undefined}>
              {l}
            </div>
          ))}
        </div>
      </aside>
      <main className="login-main">
        <form className="login-form" onSubmit={submit}>
          <div>
            <h1>Sign in</h1>
            <p className="muted" style={{ marginTop: 4 }}>
              Use the admin or viewer account created during setup.
            </p>
          </div>
          <div className="field">
            <label htmlFor="username">Username</label>
            <input id="username" className="input" autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} autoFocus />
          </div>
          <div className="field">
            <label htmlFor="password">Password</label>
            <input id="password" className="input" type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </div>
          <ErrorBanner error={error} />
          <button className="btn btn-primary" type="submit" disabled={busy} style={{ height: 40 }}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          {import.meta.env.DEV && (
            <p className="muted" style={{ fontSize: 13 }}>
              Development defaults: admin / Admin123!, viewerA or viewerB / Viewer123!
            </p>
          )}
        </form>
      </main>
    </div>
  );
}
