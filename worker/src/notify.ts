import type { AlertRule, StoredAlert } from "@logs/core";

export interface NotifyResult {
  status: string; // stored in alerts.notify_status
  ok: boolean;
}

/**
 * Generic JSON webhook. "text" makes it work as-is with Slack/Mattermost/Google Chat
 * incoming webhooks (Discord reads "content"); the structured "alert" object is for
 * anything else (n8n, Zapier -> email, a SOAR, webhook.site for testing).
 */
export function buildPayload(alert: StoredAlert, rule: AlertRule, publicUrl?: string) {
  const link = publicUrl ? `${publicUrl.replace(/\/$/, "")}/alerts?focus=${alert.id}` : undefined;
  const text = `[Log Management] ${alert.message} (tenant ${alert.tenant}, severity ${alert.severity})${link ? ` ${link}` : ""}`;
  return {
    text,
    content: text,
    alert: {
      id: String(alert.id),
      rule_id: rule.id,
      rule: rule.name,
      tenant: alert.tenant,
      severity: alert.severity,
      group_by: alert.group_by,
      group_key: alert.group_key,
      event_count: alert.event_count,
      first_seen: new Date(alert.first_seen).toISOString(),
      last_seen: new Date(alert.last_seen).toISOString(),
      message: alert.message,
      search: alert.query,
      url: link,
    },
  };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** POST with a timeout; retries network errors and 5xx (not 4xx) up to 3 attempts. */
export async function sendWebhook(url: string, payload: unknown, timeoutMs = 5000): Promise<NotifyResult> {
  let last = "";
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "user-agent": "log-management-alerts/1.0" },
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(timeoutMs),
      });
      if (res.ok) return { ok: true, status: `sent (HTTP ${res.status})` };
      last = `HTTP ${res.status}`;
      if (res.status < 500) break;
    } catch (err) {
      last = (err as Error).name === "TimeoutError" ? "timeout" : (err as Error).message;
    }
    if (attempt < 3) await sleep(attempt * 1000);
  }
  return { ok: false, status: `failed: ${last}` };
}
