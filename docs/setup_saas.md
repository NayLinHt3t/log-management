# SaaS / cloud setup

The SaaS deployment is the appliance stack on a public cloud VM, plus
`docker-compose.saas.yml`, which:

* gives Caddy a trusted Let's Encrypt certificate for your domain (`TLS_MODE=acme`),
* stops publishing the database port at all,
* sets `PUBLIC_URL` so alert notifications link back to the UI.

Reviewers then get an HTTPS URL, a login, and the ingest endpoints (HTTPS and syslog 514).

## 1. Create a VM

Any provider works: AWS EC2, Azure, Google Cloud, DigitalOcean, Oracle Cloud and so on. Use a
student credit or free tier if you have one.

| | Recommended |
|---|---|
| Image | Ubuntu Server 22.04 or 24.04 LTS (x86_64 or arm64; both images build) |
| Size | 2 vCPU / 4 GB RAM is enough for the demo (4 vCPU / 8 GB to match the appliance spec) |
| Disk | 30-40 GB |
| Public IP | static / elastic IP, so DNS does not break after a reboot |

Firewall / security group, inbound:

| Port | Why | Source |
|---|---|---|
| 22/tcp | SSH | your IP only |
| 80/tcp | Let's Encrypt HTTP-01 challenge, HTTP → HTTPS redirect | anywhere |
| 443/tcp | UI and API (HTTPS) | anywhere (or the reviewers' networks) |
| 514/udp, 514/tcp | syslog | the senders' IPs (or anywhere for the review period) |

Examples: on AWS, a security group with these rules; on Azure, NSG inbound rules; on GCP, a
VPC firewall rule with a target tag. Docker publishes ports through iptables, so the
provider-level firewall is the one that counts.

## 2. Point a domain at the VM

Let's Encrypt only issues certificates for domain names, so create a DNS **A record**, for
example `logs.example.com → <VM public IP>`.

No domain? Two free options:

* **sslip.io, no sign-up.** `<VM IP with dashes>.sslip.io` already resolves to that IP, so for
  a VM at 203.0.113.10 set `DOMAIN=203-0-113-10.sslip.io`. Let's Encrypt issues certificates for
  these names through the HTTP-01 challenge (port 80 must be open). The name changes if the IP
  changes, so use a static IP.
* **DuckDNS.** Sign in at https://www.duckdns.org, create `yourname.duckdns.org`, and set its IP
  to the VM's public IP.

Check the name with `dig +short <name>` (it must print the VM IP).

Without any domain you can still deploy. Leave `DOMAIN` empty, and Caddy serves the VM's IP
with a self-signed certificate (allowed by the assignment when documented; reviewers click
through one warning or use `curl -k`).

## 3. Install and start

SSH into the VM, then:

```bash
sudo apt-get update && sudo apt-get install -y git curl python3 netcat-openbsd
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker "$USER" && newgrp docker

git clone <repository-url> log-management && cd log-management
cp .env.example .env
# set the domain and switch Caddy to Let's Encrypt
sed -i 's/^DOMAIN=.*/DOMAIN=logs.example.com/; s/^TLS_MODE=.*/TLS_MODE=acme/' .env

./run.sh saas          # generates secrets, builds, starts, waits, prints logins
```

`./run.sh saas` remembers the mode (`LOGMGMT_MODE=saas` in `.env`), so later
`./run.sh up/down/logs/status` use the SaaS compose files automatically. The same, without
the script:

```bash
docker compose -f docker-compose.yml -f docker-compose.saas.yml up -d --build
```

On the first HTTPS request, Caddy obtains the certificate (usually 5-20 seconds). Its logs
show the progress:

```bash
./run.sh logs web      # look for "certificate obtained successfully"
```

## 4. Verify

```bash
curl -sI https://logs.example.com | head -1                       # HTTP/2 200, no -k needed
echo | openssl s_client -connect logs.example.com:443 -servername logs.example.com 2>/dev/null \
  | openssl x509 -noout -issuer -dates                              # issuer: Let's Encrypt
curl -s http://logs.example.com -o /dev/null -w '%{http_code} %{redirect_url}\n'   # 301 https://...

# from your laptop: the acceptance tests over the internet
python3 samples/post_logs.py --url https://logs.example.com --key <INGEST_API_KEY>
./samples/send_syslog.sh logs.example.com 514 both
python3 samples/simulate.py --url https://logs.example.com --key <INGEST_API_KEY> --backfill 24
```

The sender scripts need `--key`, because your laptop's `.env` does not have the VM's key;
`./run.sh info` on the VM prints it.

## 5. Give reviewers access

Send them:

* the URL `https://logs.example.com`
* `admin` and its password (from `./run.sh info`), plus `viewerA` / `viewerB` and the viewer
  password, to test RBAC
* the ingest key, plus the commands from section 4, the Postman collection
  (`postman/LogManagement.postman_collection.json`, set `baseUrl` and `ingestKey`), and the
  syslog address `logs.example.com:514`

Better: create dedicated accounts for the reviewers on the Admin page, and a tenant-bound
ingest key on Sources → Ingest API keys. Remove them after the review.

## 6. Automate VM creation (optional)

[`deploy/cloud-init.yaml`](../deploy/cloud-init.yaml) turns a fresh Ubuntu VM into a running
deployment on first boot. Paste it as *user data* when creating the VM:

* AWS: Advanced details → User data
* Azure: Advanced → Custom data
* GCP: metadata key `user-data`
* DigitalOcean: User data

First edit `REPO_URL` and `DOMAIN` at the top. When the VM is up, read the generated logins
with `sudo cat /var/log/logmgmt-install.log` or `sudo /opt/log-management/run.sh info`.

## 7. Hardening checklist for an internet-facing deployment

* [x] HTTPS only (HTTP redirects), HSTS with the real certificate, strict CSP
* [x] random secrets in `.env` (created by `run.sh`); `.env` is git-ignored, keep it `chmod 600`
* [x] database not reachable from outside (no published port in SaaS mode)
* [x] login rate limiting, argon2id passwords, 8 h tokens, hashed and revocable API keys
* [x] containers run as non-root (except Caddy and Postgres, which use their official images)
* [ ] restrict 22/tcp and 514 to known IPs in the cloud firewall
* [ ] after the review: rotate `ADMIN_PASSWORD`, revoke reviewer keys and accounts
* [ ] back up the database regularly (`pg_dump`, or a disk snapshot)
* [ ] turn on automatic security updates: `sudo apt-get install -y unattended-upgrades`

## 8. Cost and clean-up

The demo runs on the smallest general-purpose VMs (about 1 GB RAM in use). When you are done,
delete the VM, its disk and its static IP; otherwise the static IP keeps costing money on most
providers.

## Troubleshooting

* **The certificate is not issued**: DNS must already point at the VM, port 80 must be open
  (the HTTP-01 challenge), and the domain must be exactly the one in `DOMAIN`. Check with
  `./run.sh logs web`. Let's Encrypt rate-limits repeated failures, so fix DNS first, then run
  `docker compose restart web`.
* **Syslog does not arrive**: some providers block UDP until a rule allows it. Try TCP:
  `./samples/send_syslog.sh logs.example.com 514 tcp`.
* **Out of memory while building on a 1 GB VM**: add swap
  (`sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile`)
  or use a 2 GB+ VM.
