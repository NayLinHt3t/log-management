import { useMemo, useState } from "react";
import { Bar, BarChart, BarStack, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { fmtCompact, fmtFull, fmtNum, tickFormatter } from "../format";
import { sortSources, sourceColor, sourceLabel } from "../sources";

type Row = Record<string, number | string>;

function TimelineTooltip({
  active,
  payload,
  sources,
  bucket,
}: {
  active?: boolean;
  payload?: { payload: Row }[];
  sources: string[];
  bucket: string;
}) {
  if (!active || !payload?.length) return null;
  const row = payload[0].payload;
  const total = Number(row.total ?? 0);
  return (
    <div className="tooltip">
      <div className="tooltip-title">
        {fmtFull(String(row.t))} <span className="muted">({bucket})</span>
      </div>
      {sources.map((s) => (
        <div className="tooltip-row" key={s}>
          <i className="key" style={{ background: sourceColor(s) }} aria-hidden="true" />
          <strong>{fmtNum(Number(row[s] ?? 0))}</strong>
          <span>{sourceLabel(s)}</span>
        </div>
      ))}
      <div className="tooltip-total">
        <span className="ink-2">Total</span>
        <strong className="num">{fmtNum(total)}</strong>
      </div>
    </div>
  );
}

/** Events per time bucket, stacked by source. Every value is also reachable via the table view. */
export function Timeline({
  data,
  sources,
  spanMs,
  bucket,
  stale,
  height = 220,
}: {
  data: Row[];
  sources: string[];
  spanMs: number;
  bucket: string;
  stale?: boolean;
  height?: number;
}) {
  const [asTable, setAsTable] = useState(false);
  const ordered = useMemo(() => sortSources(sources), [sources]);
  const fmt = useMemo(() => tickFormatter(spanMs), [spanMs]);
  const total = data.reduce((n, r) => n + Number(r.total ?? 0), 0);
  const peak = data.reduce<Row | null>((best, r) => (!best || Number(r.total) > Number(best.total) ? r : best), null);

  return (
    <div className={`chart${stale ? " stale" : ""}`}>
      {asTable ? (
        <div className="table-wrap" style={{ maxHeight: height + 40, overflowY: "auto" }}>
          <table className="table">
            <thead>
              <tr>
                <th>Time ({bucket})</th>
                {ordered.map((s) => (
                  <th key={s} style={{ textAlign: "right" }}>
                    {sourceLabel(s)}
                  </th>
                ))}
                <th style={{ textAlign: "right" }}>Total</th>
              </tr>
            </thead>
            <tbody>
              {data
                .filter((r) => Number(r.total) > 0)
                .map((r) => (
                  <tr key={String(r.t)}>
                    <td className="nowrap">{fmtFull(String(r.t))}</td>
                    {ordered.map((s) => (
                      <td key={s} className="num" style={{ textAlign: "right" }}>
                        {fmtNum(Number(r[s] ?? 0))}
                      </td>
                    ))}
                    <td className="num" style={{ textAlign: "right", fontWeight: 650 }}>
                      {fmtNum(Number(r.total))}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div
          role="img"
          aria-label={`Events over time by source: ${fmtNum(total)} events${peak && total ? `, peak ${fmtNum(Number(peak.total))} at ${fmtFull(String(peak.t))}` : ""}`}
          style={{ height }}
        >
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 6, right: 4, bottom: 0, left: -6 }} barCategoryGap="16%">
              <CartesianGrid vertical={false} stroke="var(--grid)" />
              <XAxis
                dataKey="t"
                tickFormatter={fmt}
                tick={{ fill: "var(--muted)", fontSize: 12 }}
                tickLine={false}
                axisLine={{ stroke: "var(--axis)" }}
                minTickGap={56}
              />
              <YAxis
                allowDecimals={false}
                tickFormatter={fmtCompact}
                tick={{ fill: "var(--muted)", fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                width={44}
              />
              <Tooltip
                cursor={{ fill: "var(--hover-wash)" }}
                isAnimationActive={false}
                content={(props) => (
                  <TimelineTooltip
                    active={props.active}
                    payload={props.payload as unknown as { payload: Row }[]}
                    sources={ordered}
                    bucket={bucket}
                  />
                )}
              />
              <BarStack radius={[4, 4, 0, 0]}>
                {ordered.map((s) => (
                  <Bar
                    key={s}
                    dataKey={s}
                    name={sourceLabel(s)}
                    fill={sourceColor(s)}
                    stroke="var(--surface)"
                    strokeWidth={1}
                    maxBarSize={24}
                    isAnimationActive={false}
                  />
                ))}
              </BarStack>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
      <div className="legend">
        {ordered.map((s) => (
          <span key={s}>
            <i className="swatch" style={{ background: sourceColor(s) }} aria-hidden="true" />
            {sourceLabel(s)}
          </span>
        ))}
        <span className="spacer" />
        <button type="button" className="btn btn-ghost btn-sm" onClick={() => setAsTable(!asTable)}>
          {asTable ? "Show chart" : "Show as table"}
        </button>
      </div>
    </div>
  );
}
