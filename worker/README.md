# worker: alerts, retention, partitions

Background jobs that need exactly one runner. If several workers start, a PostgreSQL advisory
lock elects the leader; the lock is released automatically if that process dies.

| Job | Interval | What it does |
|---|---|---|
| Alert rules | `ALERT_INTERVAL_SECONDS` (15 s) | For each enabled rule, count matching events per group in the window (`evaluateRule` in `@logs/core`). New hits create an alert; hits that continue an active alert update it. Each new alert is sent once to the rule's `webhook_url` or `ALERT_WEBHOOK_URL` (JSON, 5 s timeout, 3 attempts); the delivery status is stored on the alert. |
| Partitions | `MAINTENANCE_INTERVAL_MINUTES` (10 min) | Pre-creates today plus 2 days of daily partitions for every tenant. |
| Retention | same | `drop_expired_partitions(RETENTION_DAYS)` drops whole days older than the retention (per-tenant override); deletes alerts older than `ALERT_HISTORY_DAYS` (90). |

Webhook payload:

```json
{
  "text": "[Log Management] Brute-force login (...): 6 matching events from src_ip 203.0.113.66 in 5 min (threshold 5) (tenant demoA, severity 8) https://host/alerts?focus=12",
  "content": "same as text (Discord)",
  "alert": { "id": "12", "rule": "...", "tenant": "demoA", "severity": 8, "group_by": "src_ip",
             "group_key": "203.0.113.66", "event_count": 6, "first_seen": "...", "last_seen": "...",
             "search": "action:login outcome:failure src_ip:203.0.113.66", "url": "https://host/alerts?focus=12" }
}
```

`text` makes it work unchanged with Slack, Mattermost or Google Chat incoming webhooks. For
email, point the webhook at n8n, Zapier or similar.
