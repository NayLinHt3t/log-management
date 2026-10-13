# frontend: web console

React 19 + Vite + Recharts, served by Caddy in production (`/srv`) and by Vite in development
(`npm run dev`, which proxies `/api` to `localhost:3000`).

| Page | What it shows |
|---|---|
| Dashboard | event count, timeline stacked by source (with a table view), failed logins, high severity, denies, unique IPs, open alerts, latest events (5 s refresh), Top source IPs / users / event types, events by source, severity mix, recent alerts |
| Search | the query language, expandable rows (normalized fields next to the original record), click a value to add it as a filter, keyset "load more", CSV export |
| Alerts | open, acknowledged and closed alerts with notification status; rules with an editor and a "Test rule" dry run |
| Sources | how to send data (commands for this host), file upload, pipeline health (service heartbeats), ingest API keys |
| Admin | tenants (retention, stored days) and users/roles; admins only |

The time range, tenant, source and query filters live in the URL, so every view can be shared
and the Dashboard and Search pages keep the same slice. New alerts trigger a toast from a
10-second poll in the layout.

**Design notes**

* The chrome is monochrome. Colour is reserved for data and severity. Each log source has
  one fixed colour from a colour-vision-deficiency-checked palette, and the colour follows the
  source, so filtering never repaints the others. Severity uses a separate status palette,
  always next to a number and a label.
* Type is Atkinson Hyperlegible Next and Mono (self-hosted, so the appliance works offline).
  They were chosen because analysts mostly read IPs, hashes and user names, where 0/O and
  1/l/I must not be confused.
* Light and dark themes (system default, or the toggle in the header); keyboard focus rings;
  reduced motion respected; layouts down to phone width.

```bash
npm run dev -w frontend      # http://localhost:5173 (start the backend first)
npm run build -w frontend    # type-check + production build into dist/
```
