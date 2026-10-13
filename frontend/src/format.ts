const nf = new Intl.NumberFormat();
const compactNf = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

export const fmtNum = (n: number | null | undefined) => (n === null || n === undefined ? "–" : nf.format(n));
export const fmtCompact = (n: number) => (Math.abs(n) >= 1000 ? compactNf.format(n) : nf.format(n));

const timeFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" });
const hmFmt = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" });
const dayFmt = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" });
const dayHmFmt = new Intl.DateTimeFormat(undefined, { weekday: "short", hour: "2-digit", minute: "2-digit" });
const fullFmt = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "numeric",
  hour: "2-digit",
  minute: "2-digit",
  second: "2-digit",
});

export const fmtTime = (iso: string) => timeFmt.format(new Date(iso));
export const fmtFull = (iso: string | null | undefined) => (iso ? fullFmt.format(new Date(iso)) : "–");

const isToday = (d: Date) => d.toDateString() === new Date().toDateString();
/** Short timestamp for tables: time only for today, otherwise date + time. */
export const fmtWhen = (iso: string) => {
  const d = new Date(iso);
  return isToday(d) ? timeFmt.format(d) : `${dayFmt.format(d)} ${hmFmt.format(d)}`;
};

/** Axis ticks adapt to the visible range. */
export function tickFormatter(spanMs: number) {
  if (spanMs <= 36 * 3600_000) return (iso: string) => hmFmt.format(new Date(iso));
  if (spanMs <= 8 * 86_400_000) return (iso: string) => dayHmFmt.format(new Date(iso));
  return (iso: string) => dayFmt.format(new Date(iso));
}

export function relative(iso: string | null | undefined) {
  if (!iso) return "never";
  const s = Math.round((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 5) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export const timeZoneName = () => {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone;
  } catch {
    return "local time";
  }
};

export type SevLevel = "low" | "medium" | "high" | "critical";
export const severityLevel = (s: number): SevLevel =>
  s >= 9 ? "critical" : s >= 7 ? "high" : s >= 4 ? "medium" : "low";
export const SEV_LABEL: Record<SevLevel, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};
