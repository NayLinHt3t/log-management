import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Fetch helper that keeps the previous data while reloading (no skeleton flash) and can
 * poll. `deps` re-run the loader; `intervalMs` refreshes in the background.
 */
export function useLoader<T>(
  loader: (signal: AbortSignal) => Promise<T>,
  deps: unknown[],
  intervalMs?: number,
) {
  const [data, setData] = useState<T | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const loaderRef = useRef(loader);
  useEffect(() => {
    loaderRef.current = loader; // always call the latest closure (runs before the effect below)
  });
  const ctrlRef = useRef<AbortController | null>(null);

  const run = useCallback(async () => {
    ctrlRef.current?.abort();
    const ctrl = new AbortController();
    ctrlRef.current = ctrl;
    setLoading(true);
    try {
      const result = await loaderRef.current(ctrl.signal);
      if (!ctrl.signal.aborted) {
        setData(result);
        setError(null);
      }
    } catch (err) {
      if (!ctrl.signal.aborted && (err as Error).name !== "AbortError") setError((err as Error).message);
    } finally {
      if (!ctrl.signal.aborted) setLoading(false);
    }
  }, []);

  useEffect(() => {
    void run();
    return () => ctrlRef.current?.abort();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);

  useEffect(() => {
    if (!intervalMs) return;
    const t = setInterval(() => {
      if (document.visibilityState === "visible") void run();
    }, intervalMs);
    return () => clearInterval(t);
  }, [intervalMs, run]);

  return { data, error, loading, reload: run, setData };
}

/** Persisted per-viewer preference (falls back to memory when storage is unavailable). */
export function usePref<T>(key: string, initial: T) {
  const [value, setValue] = useState<T>(() => {
    try {
      const raw = localStorage.getItem(key);
      return raw === null ? initial : (JSON.parse(raw) as T);
    } catch {
      return initial;
    }
  });
  const set = useCallback(
    (v: T) => {
      setValue(v);
      try {
        localStorage.setItem(key, JSON.stringify(v));
      } catch {
        /* ignore */
      }
    },
    [key],
  );
  return [value, set] as const;
}
