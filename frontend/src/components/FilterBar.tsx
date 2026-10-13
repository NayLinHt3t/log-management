import { useEffect, useState, type FormEvent } from "react";
import { useUser } from "../auth";
import { PRESETS, timeWindow, useFilters, type PresetId } from "../filters";
import { timeZoneName } from "../format";
import { SOURCES, sourceColor, sourceLabel } from "../sources";
import { useAppData } from "./Layout";
import { IconChevron, IconRefresh, IconSearch } from "./Icons";
import { usePopover } from "./ui";

const toLocalInput = (iso: string) => {
  const d = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
};

function SourcePicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const { open, setOpen, ref } = usePopover();
  const label =
    value.length === 0 ? "All sources" : value.length === 1 ? sourceLabel(value[0]) : `${value.length} sources`;
  const toggle = (s: string) => onChange(value.includes(s) ? value.filter((x) => x !== s) : [...value, s]);
  return (
    <div className="popover-anchor" ref={ref}>
      <button className="btn" aria-haspopup="true" aria-expanded={open} onClick={() => setOpen(!open)}>
        {value.length === 1 && <span className="swatch" style={{ background: sourceColor(value[0]) }} />}
        {label}
        <IconChevron />
      </button>
      {open && (
        <div className="popover" role="menu">
          <button className="menu-item" role="menuitemcheckbox" aria-checked={value.length === 0} onClick={() => onChange([])}>
            <input type="checkbox" readOnly checked={value.length === 0} tabIndex={-1} />
            All sources
          </button>
          <div className="menu-sep" />
          {SOURCES.map((s) => (
            <button key={s} className="menu-item" role="menuitemcheckbox" aria-checked={value.includes(s)} onClick={() => toggle(s)}>
              <input type="checkbox" readOnly checked={value.includes(s)} tabIndex={-1} />
              <span className="swatch" style={{ background: sourceColor(s) }} />
              {sourceLabel(s)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

const QUERY_EXAMPLES: [string, string][] = [
  ["user:alice", "exact field match"],
  ["src_ip:10.0.0.0/8", "CIDR range (also dst_ip, ip)"],
  ["action:login outcome:failure", "terms are combined with AND"],
  ["severity:>=7", "numbers: >, >=, <, <=, 1..5"],
  ["host:WIN*", "wildcard, case-insensitive"],
  ["-source:firewall", "exclude"],
  ['"DNS blocked"', "free text in the original record"],
  ["raw.eventName:CreateUser", "a field of the original record"],
  ["tag:ts_restamped", "events with a tag"],
];

function QueryHelp({ onPick }: { onPick: (q: string) => void }) {
  const { open, setOpen, ref } = usePopover();
  return (
    <div className="popover-anchor" ref={ref}>
      <button type="button" className="btn btn-ghost" aria-expanded={open} onClick={() => setOpen(!open)}>
        Syntax
      </button>
      {open && (
        <div className="popover popover-right" style={{ width: 360 }}>
          <p className="muted" style={{ padding: "6px 10px", fontSize: 13 }}>
            Fields: source, event_type, user, src_ip, dst_ip, host, action, outcome, severity, process, rule, tag,
            region, service.
          </p>
          {QUERY_EXAMPLES.map(([q, d]) => (
            <button
              key={q}
              type="button"
              className="menu-item"
              onClick={() => {
                onPick(q);
                setOpen(false);
              }}
            >
              <code style={{ minWidth: 170 }}>{q}</code>
              <span className="muted" style={{ fontSize: 12.5 }}>
                {d}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function FilterBar({ onRefresh, refreshing }: { onRefresh?: () => void; refreshing?: boolean }) {
  const user = useUser();
  const { tenants } = useAppData();
  const { filters, setFilters } = useFilters();
  const [q, setQ] = useState(filters.q);
  useEffect(() => setQ(filters.q), [filters.q]);

  const setRange = (range: PresetId) => {
    if (range === "custom") {
      const w = timeWindow(filters);
      setFilters({ range, from: w.from, to: w.to });
    } else setFilters({ range, from: undefined, to: undefined });
  };
  const submit = (e: FormEvent) => {
    e.preventDefault();
    setFilters({ q: q.trim() });
  };

  return (
    <form className="filters" role="search" aria-label="Filters for every chart and table on this page" onSubmit={submit}>
      <div className="segmented" role="group" aria-label="Time range">
        {PRESETS.map((p) => (
          <button type="button" key={p.id} title={p.title} aria-pressed={filters.range === p.id} onClick={() => setRange(p.id)}>
            {p.label}
          </button>
        ))}
        <button type="button" aria-pressed={filters.range === "custom"} onClick={() => setRange("custom")}>
          Custom
        </button>
      </div>
      {filters.range === "custom" && (
        <div className="custom-range">
          <input
            className="input"
            type="datetime-local"
            aria-label="From"
            value={filters.from ? toLocalInput(filters.from) : ""}
            onChange={(e) => e.target.value && setFilters({ from: new Date(e.target.value).toISOString() })}
          />
          <span className="muted">to</span>
          <input
            className="input"
            type="datetime-local"
            aria-label="To"
            value={filters.to ? toLocalInput(filters.to) : ""}
            onChange={(e) => e.target.value && setFilters({ to: new Date(e.target.value).toISOString() })}
          />
        </div>
      )}
      {user.tenant ? (
        <span className="tenant-lock" title="Your account can only see this tenant">
          Tenant {user.tenant}
        </span>
      ) : (
        <select
          className="select"
          aria-label="Tenant"
          value={filters.tenant}
          onChange={(e) => setFilters({ tenant: e.target.value })}
        >
          <option value="">All tenants</option>
          {tenants.map((t) => (
            <option key={t.id} value={t.id}>
              {t.id}
            </option>
          ))}
        </select>
      )}
      <SourcePicker value={filters.sources} onChange={(sources) => setFilters({ sources })} />
      <input
        className="input query"
        type="search"
        aria-label="Search query"
        placeholder='user:alice src_ip:10.0.0.0/8 severity:>=7 "DNS blocked"'
        value={q}
        onChange={(e) => setQ(e.target.value)}
        spellCheck={false}
        autoCapitalize="off"
      />
      <QueryHelp onPick={(term) => setQ((cur) => (cur ? `${cur} ${term}` : term))} />
      <button className="btn btn-primary" type="submit">
        <IconSearch /> Search
      </button>
      {onRefresh && (
        <button type="button" className="btn btn-ghost" onClick={onRefresh} title={`Times in ${timeZoneName()}`}>
          <IconRefresh style={refreshing ? { opacity: 0.4 } : undefined} /> Refresh
        </button>
      )}
    </form>
  );
}
