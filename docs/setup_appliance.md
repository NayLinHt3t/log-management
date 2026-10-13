# Appliance setup (single machine or VM)

The appliance runs the whole system on one host with Docker Compose: PostgreSQL, the API, the
syslog/file collector, the background worker and the HTTPS edge (Caddy).

## 1. Requirements

| | Minimum |
|---|---|
| OS | Ubuntu 22.04 or 24.04 (any Linux with Docker works; macOS with Docker Desktop is fine for a demo) |
| CPU / RAM / disk | 4 vCPU, 8 GB RAM, 40 GB disk (the stack itself uses about 1 GB RAM at demo volume) |
| Software | Docker Engine 24+ with the Compose v2 plugin, `git`, `curl`; `python3` and `nc` for the sample senders |
| Ports | 80/tcp and 443/tcp (UI, API), 514/udp and 514/tcp (syslog) reachable from browsers and log senders |

Install Docker on Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y git curl python3 netcat-openbsd
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER" && newgrp docker
docker compose version          # must print v2.x
```

## 2. Get the code

```bash
git clone <repository-url> log-management
cd log-management
```

(Or copy the project folder to the machine; nothing else is needed.)

## 3. Start: one command

```bash
./run.sh up            # or: make up
```

`run.sh up`:

1. creates `.env` from `.env.example` and replaces every `change-me` value with a random
   secret (database password, JWT secret, admin/viewer passwords, ingest API key). An
   existing `.env` keeps its values; settings it lacks are added from `.env.example`;
2. creates `data/inbox/demoA` and `data/inbox/demoB` for file drops;
3. builds the images and starts the containers (`docker compose up -d --build`; the first
   build takes 2-4 minutes);
4. waits until `https://localhost/api/health` answers, then prints:

```
Log Management is running
  UI / API     https://192.168.1.50   (also https://localhost; self-signed certificate unless TLS_MODE=acme)
  Admin        admin:Xk3...   
  Viewers      viewerA (tenant demoA), viewerB (tenant demoB), password: 7Qp...
  Ingest key   lm_...   (header X-API-Key)
  Syslog       udp/tcp 192.168.1.50:514
  Inbox        ./data/inbox/<tenant>/   (JSON, NDJSON, CloudTrail, CSV, .log)
```

`./run.sh info` prints this again at any time. On first start the backend applies the
database migrations and creates the demo tenants (`demoA`, `demoB`), the three users and
three default alert rules.

## 4. Open the UI

Browse to `https://<appliance-ip>` (or `https://localhost` on the machine itself). The
certificate comes from Caddy's internal CA, so the browser warns once. Choose
*Advanced → Continue*. Log in as `admin`.

> Why self-signed: an appliance on a LAN has no public domain for Let's Encrypt. The assignment
> allows a documented self-signed certificate. Caddy issues a certificate for whatever host
> name or IP you use. To trust it on a client, export Caddy's root CA:
> `docker compose cp web:/data/caddy/pki/authorities/local/root.crt ./appliance-root.crt`
> and import it into the client's trust store. For a trusted certificate with a real domain,
> see [setup_saas.md](setup_saas.md).

## 5. Send data and check the acceptance list

`./run.sh demo` does all of the following in one go. Step by step:

**Syslog (nc / logger), visible in the UI within seconds**

```bash
./samples/send_syslog.sh <appliance-ip> 514 both     # firewall lines over UDP, router lines over TCP
echo '<134>Aug 20 12:44:56 fw01 vendor=demo product=ngfw action=deny src=10.0.1.10 dst=8.8.8.8 spt=5353 dpt=53 proto=udp msg=DNS blocked policy=Block-DNS' | nc -u -w1 <appliance-ip> 514
logger -n <appliance-ip> -P 514 -d "hello from logger"   # Linux util-linux logger, RFC 5424
```

Then **Search** for `source:firewall` or `rule:Block-DNS`. Syslog has no tenant field, so
messages go to `SYSLOG_DEFAULT_TENANT` (demoA), or to a tenant mapped from the sender's IP
with `SYSLOG_TENANT_MAP=10.20.0.0/16=demoB`.

**HTTP `POST /api/ingest` with the sample JSON, then search for it**

```bash
python3 samples/post_logs.py --url https://<appliance-ip> --insecure    # the assignment's samples 4.3-4.7
# or with curl:
curl -k -X POST https://<appliance-ip>/api/ingest -H "X-API-Key: $(grep ^INGEST_API_KEY .env | cut -d= -f2)" \
  -H "Content-Type: application/json" \
  -d '{"tenant":"demoA","source":"api","event_type":"app_login_failed","user":"alice","ip":"203.0.113.7","reason":"wrong_password","@timestamp":"2025-08-20T07:20:00Z"}'
```

Search `user:alice`. The sample is dated 2025-08-20, older than the 7-day retention, so it is
stored with the arrival time and tagged `ts_restamped`; the original time is in the raw record
(see *Timestamp policy* in [architecture.md](architecture.md#timestamp-policy)).

**Point the system at AWS / M365 / AD files, then check normalization**

```bash
cp samples/aws_cloudtrail.json samples/m365_audit.json data/inbox/demoB/
cp samples/ad_security_events.csv data/inbox/demoA/
```

Within 5 seconds the files move to `data/inbox/processed/` with a `.result.json` report. Or
upload them on the **Sources** page. In **Search**, expand a row to see the normalized fields
next to the original record (for example `source:aws outcome:failure` finds the failed root
console login).

**Dashboard.** The Top source IPs, Top users and Top event types lists, the timeline, and the
time range, tenant and source filters all update together. Click any value to drill down.

**Alert rule and notification**

1. **Alerts → Rules → New rule**: match `action:login outcome:failure`, at least 3 events from
   the same source IP within 5 minutes. Optionally paste a https://webhook.site URL as the
   webhook. Press **Test rule**, then **Create rule**.
2. `python3 samples/simulate.py --url https://<appliance-ip> --insecure --scenario bruteforce`
3. Within about 15 seconds: a toast appears, the Alerts badge counts up, the alert is listed
   with `Notification: sent (HTTP 200)`, and webhook.site shows the JSON payload.

**RBAC.** Log in as `viewerA`: the tenant selector is replaced by a fixed "Tenant demoA",
every page shows only demoA data, there is no Admin page, and asking the API for demoB returns
`403`:

```bash
TOKEN=$(curl -ks https://localhost/api/auth/login -H 'content-type: application/json' \
  -d "{\"username\":\"viewerA\",\"password\":\"$(grep ^VIEWER_PASSWORD .env | cut -d= -f2)\"}" | python3 -c 'import sys,json;print(json.load(sys.stdin)["token"])')
curl -ks -o /dev/null -w '%{http_code}\n' "https://localhost/api/events?tenant=demoB" -H "Authorization: Bearer $TOKEN"   # 403
```

**More traffic.** `python3 samples/simulate.py --url https://<ip> --insecure --backfill 24`
fills the last 24 hours with history, and `--minutes 10` streams live events from all seven
sources (with brute-force bursts every minute).

## 6. Operations

| Task | Command |
|---|---|
| Status and health | `./run.sh status` |
| Logs | `./run.sh logs` or `./run.sh logs ingest` |
| Stop (keeps data) / start | `./run.sh down` / `./run.sh up` |
| Delete all data | `./run.sh reset` (removes the database and certificate volumes) |
| Update after `git pull` | `./run.sh up` (rebuilds; migrations run automatically) |
| Back up | `docker compose exec db pg_dump -U logs logs > backup.sql` |
| Database shell | `docker compose exec db psql -U logs logs` |

Configuration lives in `.env` (documented in `.env.example`). The settings you are most likely
to change:

| Setting | Default | Meaning |
|---|---|---|
| `RETENTION_DAYS` | 7 | days kept per tenant (minimum 7); per-tenant override on the Admin page |
| `SYSLOG_DEFAULT_TENANT`, `SYSLOG_TENANT_MAP` | demoA, empty | tenant for syslog senders |
| `HTTP_PORT`, `HTTPS_PORT`, `SYSLOG_PORT` | 80, 443, 514 | published ports |
| `ALERT_WEBHOOK_URL` | empty | default webhook for rules without their own |
| `LATE_EVENT_POLICY` | restamp | what to do with events older than the retention |

Restart with `./run.sh up` after editing `.env`.

## 7. Troubleshooting

* **"port is already allocated" / "address already in use"**: something else listens on 80,
  443, 514 or 5433 (the database port on localhost). `./run.sh up` checks this before starting
  and names any container that holds one of these ports, for example the database of an older
  copy of this project: stop it with `docker stop <name>`. For other programs, check with
  `sudo ss -ltnup | grep -E ':(80|443|514|5433)\b'`. Ubuntu's rsyslog does not listen on 514
  unless configured to. Otherwise set `HTTP_PORT=8080`, `HTTPS_PORT=8443`, `SYSLOG_PORT=5514`
  or `DB_PORT=5434` in `.env` and use `https://host:8443`.
* **"Docker is installed but not running"**: start Docker Desktop (macOS/Windows) or
  `sudo systemctl start docker` (Linux), then run `./run.sh up` again.
* **macOS (Docker Desktop)**: if ports below 1024 are refused, use the alternative ports
  above. Syslog from the Mac itself: `nc -u -w1 127.0.0.1 514` (macOS `logger` cannot send to
  a remote host).
* **UFW on Ubuntu**: Docker publishes ports through iptables directly, so UFW rules do not
  block them. Restrict access in the cloud or hypervisor firewall instead.
* **The browser shows a certificate error and no "Continue" option**: this happens only
  when the browser remembered HSTS for this host from a real certificate. Use the IP address,
  or clear HSTS for the host (Chrome: `chrome://net-internals/#hsts`).
* **"migration ... changed after it was applied"**: the database was created by an older
  version of the schema. For a demo database: `./run.sh reset`, then `./run.sh up`.
* **Login fails after changing `ADMIN_PASSWORD` in `.env`**: users are created only on the
  first start. Delete the user on the Admin page and restart, or use `./run.sh reset`.
* **Nothing arrives over syslog**: run `./run.sh logs ingest`, check that the sender can reach
  514/udp, and look at **Sources → Pipeline health** (UDP/TCP message counters).

## 8. Development mode (no containers for the app)

```bash
npm ci
npm run db:up        # only PostgreSQL, on localhost:5433
npm run dev          # backend :3000, ingest :5514 (syslog), worker, UI http://localhost:5173
npm test             # unit tests; INTEGRATION=1 npm test adds the API + database tests
```

`npm run dev` reads `.env` (the same file Docker uses). Without the secrets it falls back to
development defaults (admin / Admin123!, viewerA / Viewer123!, ingest key
`dev-ingest-key-change-me`).

## 9. Packaging as a VM image

No OVA is shipped. Any Ubuntu 22.04 VM image (VirtualBox, VMware, Proxmox, UTM) becomes the
appliance with sections 1-3 above. To automate them on first boot, use
[`deploy/cloud-init.yaml`](../deploy/cloud-init.yaml). It works with cloud images and with
local hypervisors that support cloud-init (for example Multipass:
`multipass launch 22.04 --cpus 4 --memory 8G --disk 40G --cloud-init deploy/cloud-init.yaml`).
