#!/usr/bin/env python3
"""
Traffic simulator for the log management demo (Python 3.8+, standard library only).

Generates realistic events for all seven sources and sends them through the real
ingestion paths:
  - firewall + router syslog  -> UDP (or TCP) port 514
  - API, CrowdStrike, AWS CloudTrail, Microsoft 365, Windows/AD -> HTTPS POST /api/ingest

Examples
  python3 samples/simulate.py                                   # 2 minutes, 5 events/s, https://localhost
  python3 samples/simulate.py --url https://logs.example.com --minutes 0 --rate 20   # until Ctrl+C
  python3 samples/simulate.py --scenario bruteforce             # 18 failed logins from one IP -> alerts
  python3 samples/simulate.py --scenario malware                # high-severity EDR detection -> alert

The ingest key is read from --key, $INGEST_API_KEY, or the INGEST_API_KEY line in ../.env.
Use --insecure with the appliance's self-signed certificate.
"""
import argparse
import json
import os
import random
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

USERS_A = ["alice", "bob", "carol", "dave", "eve", "svc_backup", "admin"]
USERS_B = ["bob@demo.local", "carol@demo.local", "frank@demo.local", "grace@demo.local", "it-admin@demo.local"]
HOSTS = ["WIN10-01", "WIN10-02", "WIN11-07", "SRV-FILE01", "DC01", "DC02"]
INTERNAL = ["10.0.1.%d" % i for i in range(10, 40)] + ["10.0.2.%d" % i for i in range(5, 25)]
EXTERNAL = ["8.8.8.8", "1.1.1.1", "142.250.72.14", "151.101.1.69", "52.94.236.248", "104.16.132.229", "185.199.108.153"]
SCANNERS = ["198.51.100.9", "203.0.113.50", "45.155.205.233", "92.63.197.48"]
OFFICE_IPS = ["198.51.100.23", "198.51.100.24", "203.0.113.7", "203.0.113.8"]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def syslog_ts():
    # RFC 3164 "Mmm dd hh:mm:ss" (strftime uses the C locale, so month names stay English)
    return datetime.now().strftime("%b %d %H:%M:%S")


# ---- syslog sources ------------------------------------------------------------------
def firewall_fields():
    r = random.random()
    if r < 0.12:  # inbound scan, blocked
        src, dst = random.choice(SCANNERS), random.choice(INTERNAL)
        dpt, action, policy = random.choice([22, 23, 445, 3389, 5900]), "deny", "Inbound-Default-Deny"
    elif r < 0.22:  # blocked outbound DNS (the assignment's sample)
        src, dst, dpt, action, policy = random.choice(INTERNAL), "8.8.8.8", 53, "deny", "Block-DNS"
    else:
        src, dst = random.choice(INTERNAL), random.choice(EXTERNAL)
        dpt, action, policy = random.choice([443, 443, 443, 80, 53, 123]), "allow", "Allow-Web"
    proto = "udp" if dpt in (53, 123) else "tcp"
    msg = {"deny": random.choice(["DNS blocked", "Port blocked", "Geo blocked"]), "allow": "session start"}[action]
    return {"host": random.choice(["fw01", "fw02"]), "vendor": "demo", "product": "ngfw", "action": action, "src": src, "dst": dst,
            "spt": random.randint(1024, 65535), "dpt": dpt, "proto": proto, "msg": msg, "policy": policy}


def firewall_line():
    f = firewall_fields()
    pri = 132 if f["action"] == "deny" else 134  # local0.warning / local0.info
    if random.random() < 0.15:  # some devices speak CEF
        sev = 7 if f["action"] == "deny" else 3
        return (
            "<%d>%s fw02 CEF:0|Acme|NGFW|9.1|%d|Traffic %s|%d|src=%s dst=%s spt=%d dpt=%d proto=%s act=%s cs1Label=Rule cs1=%s"
            % (pri, syslog_ts(), 1000 + f["dpt"], f["action"], sev, f["src"], f["dst"], f["spt"], f["dpt"], f["proto"].upper(), f["action"], f["policy"])
        )
    return "<%d>%s %s vendor=demo product=ngfw action=%s src=%s dst=%s spt=%d dpt=%d proto=%s msg=%s policy=%s" % (
        pri, syslog_ts(), f["host"], f["action"], f["src"], f["dst"], f["spt"], f["dpt"], f["proto"], f["msg"], f["policy"],
    )


def network_fields():
    event, reason, pri = random.choice(
        [
            ("link-down", "carrier-loss", 187),
            ("link-up", "carrier-restored", 190),
            ("bgp-neighbor-down", "hold-timer-expired", 187),
            ("bgp-neighbor-up", "established", 190),
            ("config-change", "commit-by-netops", 189),
            ("high-cpu", "cpu-85-percent", 188),
        ]
    )
    return {"pri": pri, "host": "r%d" % random.randint(1, 3), "if": "ge-0/0/%d" % random.randint(0, 7), "event": event,
            "mac": "aa:bb:cc:%02x:%02x:%02x" % (random.randint(0, 255), random.randint(0, 255), random.randint(0, 255)), "reason": reason}


def network_line():
    f = network_fields()
    return "<%d>%s %s if=%s event=%s mac=%s reason=%s" % (f["pri"], syslog_ts(), f["host"], f["if"], f["event"], f["mac"], f["reason"])


# ---- JSON sources (sent over HTTP) ---------------------------------------------------
def api_event(tenant):
    user = random.choice(USERS_A if tenant == "demoA" else USERS_B)
    kind = random.choices(
        ["app_login_success", "app_login_failed", "password_reset", "order_created", "api_key_created"],
        weights=[50, 12, 5, 30, 3],
    )[0]
    ev = {"tenant": tenant, "source": "api", "event_type": kind, "user": user, "ip": random.choice(OFFICE_IPS + INTERNAL[:5]), "@timestamp": now_iso()}
    if kind == "app_login_failed":
        ev["reason"] = random.choice(["wrong_password", "unknown_user", "mfa_timeout"])
    if kind == "order_created":
        ev.update({"url": "/api/orders", "method": "POST", "status_code": 201})
    return ev


def crowdstrike_event(tenant):
    if random.random() < 0.5:  # the assignment's abridged shape
        return {
            "tenant": tenant, "source": "crowdstrike", "event_type": random.choice(["malware_detected", "suspicious_script", "process_blocked"]),
            "host": random.choice(HOSTS), "process": random.choice(["powershell.exe", "rundll32.exe", "wscript.exe", "chrome.exe"]),
            "severity": random.choice([3, 4, 5, 6]), "sha256": "%064x" % random.getrandbits(256), "action": random.choice(["quarantine", "kill_process", "detect"]),
            "@timestamp": now_iso(),
        }
    return {  # native Falcon streaming detection
        "tenant": tenant, "source": "crowdstrike",
        "metadata": {"eventType": "DetectionSummaryEvent", "eventCreationTime": int(time.time() * 1000)},
        "event": {
            "ComputerName": random.choice(HOSTS), "UserName": random.choice(USERS_A), "FileName": random.choice(["powershell.exe", "certutil.exe", "excel.exe"]),
            "CommandLine": "powershell -enc SQBFAFgA...", "SHA256String": "%064x" % random.getrandbits(256),
            "Severity": random.choice([1, 2, 2, 3]), "Tactic": random.choice(["Execution", "Defense Evasion", "Discovery"]),
            "Technique": random.choice(["PowerShell", "Obfuscated Files or Information", "System Information Discovery"]),
            "DetectName": "Suspicious Activity", "LocalIP": random.choice(INTERNAL),
        },
    }


def aws_event(tenant):
    name, source = random.choice(
        [
            ("ConsoleLogin", "signin.amazonaws.com"), ("AssumeRole", "sts.amazonaws.com"), ("DescribeInstances", "ec2.amazonaws.com"),
            ("PutObject", "s3.amazonaws.com"), ("GetObject", "s3.amazonaws.com"), ("CreateUser", "iam.amazonaws.com"),
            ("RunInstances", "ec2.amazonaws.com"), ("AuthorizeSecurityGroupIngress", "ec2.amazonaws.com"),
        ]
    )
    user = random.choice(["admin", "deploy-bot", "alice", "ci-runner"])
    rec = {
        "tenant": tenant, "eventVersion": "1.08",
        "userIdentity": {"type": "IAMUser", "userName": user, "accountId": "123456789012", "arn": "arn:aws:iam::123456789012:user/%s" % user},
        "eventTime": now_iso(), "eventSource": source, "eventName": name, "awsRegion": random.choice(["ap-southeast-1", "us-east-1"]),
        "sourceIPAddress": random.choice(OFFICE_IPS + ["ec2.amazonaws.com"]), "userAgent": "aws-cli/2.15.0", "recipientAccountId": "123456789012",
    }
    if name == "ConsoleLogin":
        rec["responseElements"] = {"ConsoleLogin": "Failure" if random.random() < 0.2 else "Success"}
    if random.random() < 0.05:
        rec["errorCode"] = "AccessDenied"
    return rec


def m365_event(tenant):
    op = random.choices(["UserLoggedIn", "UserLoginFailed", "FileAccessed", "MailItemsAccessed", "Add member to role."], weights=[45, 10, 25, 18, 2])[0]
    return {
        "tenant": tenant, "CreationTime": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"), "Id": "%032x" % random.getrandbits(128),
        "Operation": op, "RecordType": 15 if "Log" in op else 6, "ResultStatus": "Failed" if op == "UserLoginFailed" else "Success",
        "UserId": random.choice(USERS_B), "ClientIP": random.choice(OFFICE_IPS) + ":%d" % random.randint(1024, 65535),
        "Workload": "AzureActiveDirectory" if "Log" in op else random.choice(["SharePoint", "Exchange", "OneDrive"]),
    }


def ad_event(tenant):
    eid = random.choices([4624, 4625, 4634, 4672, 4688, 4720, 4740], weights=[45, 12, 25, 6, 8, 2, 2])[0]
    return {
        "tenant": tenant, "EventID": eid, "TimeCreated": now_iso(), "Computer": random.choice(["DC01", "DC02", "SRV-FILE01"]),
        "TargetUserName": random.choice(USERS_A), "TargetDomainName": "DEMO", "IpAddress": random.choice(INTERNAL + OFFICE_IPS),
        "LogonType": random.choice([2, 3, 3, 10]), "Status": "0xc000006d" if eid == 4625 else "0x0",
    }


HTTP_SOURCES = [
    (api_event, ["demoA", "demoB"], 18),
    (crowdstrike_event, ["demoA"], 6),
    (aws_event, ["demoB"], 14),
    (m365_event, ["demoB"], 16),
    (ad_event, ["demoA"], 20),
]


# ---- scenarios -----------------------------------------------------------------------
def bruteforce_events():
    """18 failed logins from one attacker IP: 12 on AD (tenant demoA) and 6 on M365 (tenant demoB)."""
    attacker = "203.0.113.%d" % random.randint(60, 250)
    events = []
    for i in range(12):
        events.append({"tenant": "demoA", "source": "ad", "event_id": 4625, "event_type": "LogonFailed", "user": "demo\\%s" % random.choice(USERS_A[:5]),
                       "host": "DC01", "ip": attacker, "logon_type": 3, "@timestamp": now_iso()})
    for i in range(6):
        events.append({"tenant": "demoB", "source": "m365", "event_type": "UserLoggedIn", "user": random.choice(USERS_B), "ip": attacker,
                       "status": "Failed", "workload": "AzureActiveDirectory", "@timestamp": now_iso()})
    return attacker, events


def malware_events():
    return [{"tenant": "demoA", "source": "crowdstrike", "event_type": "malware_detected", "host": random.choice(HOSTS), "process": "mimikatz.exe",
             "severity": 9, "sha256": "%064x" % random.getrandbits(256), "action": "quarantine", "@timestamp": now_iso()}]


# ---- backfill: history for the last N hours (sent over HTTP with explicit timestamps) --
def stamp(ev, dt):
    """Put a historical timestamp into whichever field the record's format uses."""
    iso = dt.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    if "eventTime" in ev:
        ev["eventTime"] = iso
    elif "CreationTime" in ev:
        ev["CreationTime"] = dt.strftime("%Y-%m-%dT%H:%M:%S")
    elif "TimeCreated" in ev:
        ev["TimeCreated"] = iso
    elif "metadata" in ev:
        ev["metadata"]["eventCreationTime"] = int(dt.timestamp() * 1000)
    else:
        ev["@timestamp"] = iso
    return ev


def backfill(sender, hours, per_hour):
    now = datetime.now(timezone.utc)
    total, batch = 0, []
    for h in range(int(hours), 0, -1):
        start = now.timestamp() - h * 3600
        local_hour = datetime.fromtimestamp(start).hour
        busy = 1.3 if 8 <= local_hour < 18 else 0.8 if 18 <= local_hour < 23 else 0.45  # office-hours shape
        for _ in range(int(per_hour * busy * random.uniform(0.85, 1.15))):
            dt = datetime.fromtimestamp(start + random.random() * 3600, timezone.utc)
            r = random.random()
            if r < 0.35:
                ev = dict(firewall_fields(), tenant="demoA", source="firewall")
            elif r < 0.42:
                f = network_fields()
                f.pop("pri")
                ev = dict(f, tenant="demoA", source="network")
            else:
                gen, tenants, _w = random.choices(HTTP_SOURCES, weights=[w for *_x, w in HTTP_SOURCES])[0]
                ev = gen(random.choice(tenants))
            batch.append(stamp(ev, dt))
            if len(batch) >= 500:
                sender.post(batch)
                total += len(batch)
                batch = []
        print("  backfilled %2d h ago" % h)
    sender.post(batch)
    total += len(batch)
    print("backfilled %d events over the last %d hours (rejected %d)" % (total, hours, sender.rejected))


# ---- transport -----------------------------------------------------------------------
def read_env_key():
    if os.environ.get("INGEST_API_KEY"):
        return os.environ["INGEST_API_KEY"]
    for path in (os.path.join(os.path.dirname(__file__), "..", ".env"), ".env"):
        try:
            with open(path) as f:
                for line in f:
                    if line.startswith("INGEST_API_KEY="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return None


class Sender:
    def __init__(self, args):
        self.url = args.url.rstrip("/") + "/api/ingest"
        self.key = args.key
        self.ctx = ssl._create_unverified_context() if args.insecure else None
        self.syslog_addr = (args.syslog_host or urlparse(args.url).hostname, args.syslog_port)
        self.tcp = args.syslog_tcp
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.tcp_sock = None
        self.sent = {}
        self.rejected = 0

    def count(self, name, n=1):
        self.sent[name] = self.sent.get(name, 0) + n

    def syslog(self, line, name):
        data = line.encode()
        if self.tcp:
            if self.tcp_sock is None:
                self.tcp_sock = socket.create_connection(self.syslog_addr, timeout=5)
            self.tcp_sock.sendall(data + b"\n")
        else:
            self.udp.sendto(data, self.syslog_addr)
        self.count(name)

    def post(self, events):
        if not events:
            return
        req = urllib.request.Request(self.url, data=json.dumps(events).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-API-Key": self.key})
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=15) as res:
                body = json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as e:
            body = json.loads(e.read() or b"{}")
            if e.code in (401, 403):
                sys.exit("ingest refused (%s): %s" % (e.code, body.get("error")))
        self.rejected += body.get("rejected", 0)
        for err in body.get("errors", [])[:3]:
            print("  rejected:", err.get("error"), file=sys.stderr)
        for ev in events:
            self.count(ev.get("source") or ("aws" if "eventSource" in ev else "m365" if "Operation" in ev else "ad"))


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=os.environ.get("LOGMGMT_URL", "https://localhost"), help="base URL of the UI/API")
    p.add_argument("--key", default=None, help="ingest API key (default: $INGEST_API_KEY or ../.env)")
    p.add_argument("--insecure", "-k", action="store_true", help="accept a self-signed TLS certificate")
    p.add_argument("--syslog-host", default=None, help="syslog host (default: host of --url)")
    p.add_argument("--syslog-port", type=int, default=514)
    p.add_argument("--syslog-tcp", action="store_true", help="send syslog over TCP instead of UDP")
    p.add_argument("--rate", type=float, default=5, help="events per second (all sources together)")
    p.add_argument("--minutes", type=float, default=2, help="how long to run; 0 = until Ctrl+C")
    p.add_argument("--scenario", choices=["all", "bruteforce", "malware", "syslog-only", "http-only"], default="all")
    p.add_argument("--burst-every", type=float, default=60, help="seconds between brute-force bursts in 'all' (0 = none)")
    p.add_argument("--backfill", type=float, default=0, metavar="HOURS",
                   help="first send history for the last HOURS hours (max 24*6, kept by the 7-day retention)")
    p.add_argument("--backfill-rate", type=int, default=1200, metavar="N", help="events per hour for --backfill")
    args = p.parse_args()
    args.key = args.key or read_env_key()
    if not args.key and args.scenario != "syslog-only":
        sys.exit("No ingest key: pass --key, export INGEST_API_KEY, or run from the repo with a .env file")

    s = Sender(args)
    if args.backfill > 0:
        backfill(s, min(args.backfill, 144), args.backfill_rate)
        if "--minutes" not in sys.argv and args.scenario == "all":
            return  # backfill only; add --minutes N to keep sending live traffic afterwards
    if args.scenario == "bruteforce":
        attacker, evs = bruteforce_events()
        for i in range(0, len(evs), 3):
            s.post(evs[i:i + 3])
            time.sleep(2)
        print("sent %d failed logins from %s; the brute-force rule fires within ~15 s (see Alerts)" % (len(evs), attacker))
        return
    if args.scenario == "malware":
        s.post(malware_events())
        print("sent a severity-9 CrowdStrike detection; the malware rule fires within ~15 s")
        return

    end = time.time() + args.minutes * 60 if args.minutes > 0 else float("inf")
    last_report = last_burst = time.time()
    print("sending ~%.0f events/s to %s and syslog %s:%d/%s (Ctrl+C to stop)" % (
        args.rate, s.url, s.syslog_addr[0], s.syslog_addr[1], "tcp" if args.syslog_tcp else "udp"))
    try:
        while time.time() < end:
            tick = time.time()
            batch = []
            n = max(1, int(random.gauss(args.rate, args.rate * 0.25)))
            for _ in range(n):
                r = random.random()
                if args.scenario != "http-only" and r < 0.35:
                    s.syslog(firewall_line(), "firewall")
                elif args.scenario != "http-only" and r < 0.42:
                    s.syslog(network_line(), "network")
                elif args.scenario != "syslog-only":
                    gen, tenants, _w = random.choices(HTTP_SOURCES, weights=[w for *_x, w in HTTP_SOURCES])[0]
                    batch.append(gen(random.choice(tenants)))
            s.post(batch)
            if args.scenario == "all" and args.burst_every > 0 and time.time() - last_burst > args.burst_every:
                attacker, evs = bruteforce_events()
                s.post(evs)
                print("  brute-force burst from %s" % attacker)
                last_burst = time.time()
            if time.time() - last_report > 10:
                print("  sent so far:", ", ".join("%s %d" % kv for kv in sorted(s.sent.items())), "| rejected %d" % s.rejected)
                last_report = time.time()
            time.sleep(max(0, 1 - (time.time() - tick)))
    except KeyboardInterrupt:
        pass
    print("done:", ", ".join("%s %d" % kv for kv in sorted(s.sent.items())), "| rejected %d" % s.rejected)


if __name__ == "__main__":
    main()
