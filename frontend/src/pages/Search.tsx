import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, download, type EventRow, type SearchResult } from "../api";
import { addTerm, apiQuery, describeRange, useFilters } from "../filters";
import { fmtNum } from "../format";
import { useLoader } from "../hooks";
import { FilterBar } from "../components/FilterBar";
import { EventTable } from "../components/EventTable";
import { IconDownload } from "../components/Icons";
import { Empty, ErrorBanner } from "../components/ui";

export function Search() {
  const { filters, setFilters } = useFilters();
  const first = useLoader(
    (signal) => api<SearchResult>("/events", { query: { ...apiQuery(filters), limit: 100 }, signal }),
    [filters],
  );
  const [more, setMore] = useState<EventRow[]>([]);
  const [next, setNext] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState<string | null>(null);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setMore([]);
    setNext(first.data?.next_cursor ?? null);
  }, [first.data]);

  // later pages reuse the first page's exact window, so a relative range does not drift
  const pageQuery = () => ({
    ...apiQuery(filters),
    from: first.data?.from,
    to: first.data?.to,
  });

  const loadMore = async () => {
    if (!next) return;
    setLoadingMore(true);
    setMoreError(null);
    try {
      const r = await api<SearchResult>("/events", { query: { ...pageQuery(), cursor: next, limit: 100 } });
      setMore((m) => [...m, ...r.events]);
      setNext(r.next_cursor);
    } catch (err) {
      setMoreError((err as Error).message);
    } finally {
      setLoadingMore(false);
    }
  };

  const exportCsv = () =>
    download("/events/export.csv", pageQuery(), `events-${new Date().toISOString().slice(0, 16).replace(/[:T]/g, "-")}.csv`).catch(
      (err) => setMoreError((err as Error).message),
    );

  const events = [...(first.data?.events ?? []), ...more];
  const total = first.data?.total;

  return (
    <>
      <FilterBar onRefresh={first.reload} refreshing={first.loading} />
      <ErrorBanner error={first.error} />
      <section className="panel" aria-label="Search results">
        <div className="results-head">
          <strong>
            {total === null || total === undefined ? "…" : fmtNum(total)}
            {first.data?.total_capped ? "+" : ""} events
          </strong>
          <span className="muted">
            {describeRange(filters)}
            {first.data ? `, found in ${first.data.took_ms} ms` : ""}
          </span>
          <span className="spacer" />
          <span className="muted" style={{ fontSize: 13 }}>
            Click a row for every field and the original record
          </span>
          <button type="button" className="btn btn-sm" onClick={exportCsv} disabled={!events.length}>
            <IconDownload /> Export CSV
          </button>
        </div>
        {first.data && events.length === 0 ? (
          <Empty title="No events match">
            Try a wider time range, remove a filter, or check the <Link to="/sources">ingest status</Link>.
          </Empty>
        ) : (
          <div style={{ opacity: first.loading && first.data ? 0.55 : 1, transition: "opacity .2s" }}>
            <EventTable events={events} onAddTerm={(field, value) => setFilters({ q: addTerm(filters.q, field, value) })} />
          </div>
        )}
        <ErrorBanner error={moreError} />
        {next && (
          <div className="load-more">
            <button type="button" className="btn" onClick={loadMore} disabled={loadingMore}>
              {loadingMore ? "Loading…" : `Load 100 more (showing ${fmtNum(events.length)})`}
            </button>
          </div>
        )}
      </section>
    </>
  );
}
