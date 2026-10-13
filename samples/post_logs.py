#!/usr/bin/env python3
"""
POST sample JSON logs to the HTTP ingest API (Python 3.8+, standard library only).

  python3 samples/post_logs.py                                  # the assignment's samples
  python3 samples/post_logs.py samples/http_api_events.json --tenant demoA
  python3 samples/post_logs.py samples/aws_cloudtrail.json --tenant demoB --source aws
  python3 samples/post_logs.py --url https://logs.example.com --key lm_xxx

Files may hold one JSON object, an array, CloudTrail's {"Records": [...]}, or JSON Lines.
The key comes from --key, $INGEST_API_KEY, or INGEST_API_KEY in ../.env.
Use --insecure (-k) with the appliance's self-signed certificate.
"""
import argparse
import json
import os
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))


def read_key():
    if os.environ.get("INGEST_API_KEY"):
        return os.environ["INGEST_API_KEY"]
    for path in (os.path.join(HERE, "..", ".env"), ".env"):
        try:
            with open(path) as f:
                for line in f:
                    if line.startswith("INGEST_API_KEY="):
                        return line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    return None


def load(path):
    with open(path, encoding="utf-8-sig") as f:
        text = f.read().strip()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return [json.loads(line) for line in text.splitlines() if line.strip()]  # JSON Lines
    if isinstance(data, dict) and isinstance(data.get("Records"), list):
        return data["Records"]
    return data if isinstance(data, list) else [data]


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("files", nargs="*", default=[os.path.join(HERE, "assignment_samples.json")])
    p.add_argument("--url", default=os.environ.get("LOGMGMT_URL", "https://localhost"))
    p.add_argument("--key", default=None)
    p.add_argument("--tenant", help="tenant for records that do not name one")
    p.add_argument("--source", help="source hint for records without a 'source' field (aws, m365, ad, ...)")
    p.add_argument("--insecure", "-k", action="store_true", help="accept a self-signed certificate")
    args = p.parse_args()

    key = args.key or read_key()
    if not key:
        sys.exit("No ingest key: pass --key, export INGEST_API_KEY, or run from the repo with a .env file")
    ctx = ssl._create_unverified_context() if args.insecure else None
    query = urllib.parse.urlencode({k: v for k, v in (("tenant", args.tenant), ("source", args.source)) if v})
    url = args.url.rstrip("/") + "/api/ingest" + ("?" + query if query else "")

    exit_code = 0
    for path in args.files:
        records = load(path)
        req = urllib.request.Request(url, data=json.dumps(records).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "X-API-Key": key})
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=30) as res:
                body = json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as e:
            body = json.loads(e.read() or b"{}")
            exit_code = 1
        except urllib.error.URLError as e:
            sys.exit("cannot reach %s: %s (self-signed certificate? add --insecure)" % (url, e.reason))
        print("%s: %d accepted, %d rejected%s" % (
            os.path.basename(path), body.get("accepted", 0), body.get("rejected", 0),
            ", %d re-stamped (older than retention)" % body["restamped"] if body.get("restamped") else ""))
        for err in body.get("errors", [])[:10]:
            print("   record %s: %s" % (err.get("index"), err.get("error")))
        if body.get("error"):
            print("   error:", body["error"])
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
