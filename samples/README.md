# Samples and senders

| File | Content | Send it with |
|---|---|---|
| `assignment_samples.json` | the assignment's samples 4.3-4.7 (API, CrowdStrike, AWS, M365, AD) | `python3 post_logs.py` (default file) |
| `firewall.log` | sample 4.1 plus Fortinet, CEF and UFW lines | `./send_syslog.sh <host> 514 udp` |
| `network.log` | sample 4.2 plus router/switch events | `./send_syslog.sh <host> 514 tcp` |
| `http_api_events.json` | application events | `python3 post_logs.py http_api_events.json` |
| `aws_cloudtrail.json` | native CloudTrail (`{"Records": [...]}`): CreateUser, AttachUserPolicy, failed root ConsoleLogin, StopLogging denied... | inbox `data/inbox/demoB/`, upload, or `post_logs.py --tenant demoB` |
| `m365_audit.json` | native Unified Audit Log records | inbox `demoB`, upload, or `post_logs.py --tenant demoB` |
| `ad_security_events.json` / `.csv` | Windows security events (4624, 4625, 4740, 4720, 4688, 1102) | inbox `demoA`, upload, or `post_logs.py --tenant demoA` |
| `crowdstrike_detections.json` | abridged and native Falcon detections | inbox `demoA`, upload, or `post_logs.py --tenant demoA` |

Scripts (Python 3.8+ standard library and bash, nothing to install):

* `send_syslog.sh [host] [port] [udp|tcp|both]` sends the syslog samples with `nc` and one
  RFC 5424 message with `logger` where available.
* `post_logs.py [files...] [--url] [--key] [--tenant] [--source] [--insecure]` POSTs JSON
  files to `/api/ingest`.
* `simulate.py` generates realistic traffic for all seven sources over syslog and HTTPS:
  * `--minutes N --rate EPS` streams live traffic (with a brute-force burst every
    `--burst-every` seconds)
  * `--backfill 24` sends 24 hours of history
  * `--scenario bruteforce|malware` sends one burst that fires the default alert rules
  * against `npm run dev` (plain HTTP, syslog on 5514):
    `python3 simulate.py --url http://localhost:3000 --syslog-port 5514 --key dev-ingest-key-change-me`

The scripts read the ingest key from `--key`, `$INGEST_API_KEY` or `../.env`; add
`--insecure` for the appliance's self-signed certificate.
