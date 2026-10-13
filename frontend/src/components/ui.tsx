import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { severityLevel, SEV_LABEL } from "../format";
import { sourceColor, sourceLabel } from "../sources";
import { IconCheck, IconClose, IconCopy } from "./Icons";

export function Severity({ value, label = true }: { value: number; label?: boolean }) {
  const level = severityLevel(value);
  return (
    <span className={`sev ${level}`} title={`Severity ${value} of 10 (${SEV_LABEL[level]})`}>
      <i aria-hidden="true" />
      <b>{value}</b>
      {label && <span className="ink-2">{SEV_LABEL[level]}</span>}
    </span>
  );
}

export function SourceName({ source }: { source: string }) {
  return (
    <span className="row" style={{ gap: 6, flexWrap: "nowrap" }}>
      <span className="swatch" style={{ background: sourceColor(source) }} aria-hidden="true" />
      {sourceLabel(source)}
    </span>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <strong>{title}</strong>
      {children}
    </div>
  );
}

export function ErrorBanner({ error }: { error: string | null | undefined }) {
  if (!error) return null;
  return (
    <div className="banner error" role="alert">
      {error}
    </div>
  );
}

export function CopyBlock({ code }: { code: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard blocked: the text is still selectable */
    }
  };
  return (
    <div className="codeblock">
      <pre>
        <code>{code}</code>
      </pre>
      <button className="btn btn-ghost btn-sm icon-btn copy" onClick={copy} aria-label={copied ? "Copied" : "Copy to clipboard"}>
        {copied ? <IconCheck /> : <IconCopy />}
      </button>
    </div>
  );
}

export function Drawer({
  title,
  onClose,
  children,
  footer,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    ref.current?.querySelector<HTMLElement>("input, select, textarea, button")?.focus();
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <>
      <div className="backdrop" onClick={onClose} />
      <div className="drawer" role="dialog" aria-modal="true" aria-label={title} ref={ref}>
        <div className="drawer-head">
          <h2>{title}</h2>
          <button className="btn btn-ghost icon-btn" onClick={onClose} aria-label="Close">
            <IconClose />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </div>
    </>
  );
}

// ---- toasts -----------------------------------------------------------------------------
export interface ToastMsg {
  id: number;
  kind: "alert" | "success" | "error" | "info";
  title: string;
  body?: string;
  action?: { label: string; onClick: () => void };
}

const ToastCtx = createContext<(t: Omit<ToastMsg, "id">) => void>(() => undefined);
// eslint-disable-next-line react-refresh/only-export-components
export const useToast = () => useContext(ToastCtx);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastMsg[]>([]);
  const nextId = useRef(1);
  const dismiss = useCallback((id: number) => setToasts((ts) => ts.filter((t) => t.id !== id)), []);
  const push = useCallback(
    (t: Omit<ToastMsg, "id">) => {
      const id = nextId.current++;
      setToasts((ts) => [...ts.slice(-3), { ...t, id }]);
      setTimeout(() => dismiss(id), t.kind === "alert" ? 12000 : 5000);
    },
    [dismiss],
  );
  return (
    <ToastCtx.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.kind}`} role={t.kind === "alert" ? "alert" : "status"}>
            <span className="rail" aria-hidden="true" />
            <div>
              <strong>{t.title}</strong>
              {t.body && <p>{t.body}</p>}
              {t.action && (
                <button
                  className="btn btn-sm"
                  style={{ marginTop: 8 }}
                  onClick={() => {
                    t.action!.onClick();
                    dismiss(t.id);
                  }}
                >
                  {t.action.label}
                </button>
              )}
            </div>
            <button className="btn btn-ghost btn-sm icon-btn" onClick={() => dismiss(t.id)} aria-label="Dismiss">
              <IconClose />
            </button>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

/** Closes a popover on outside click / Escape. */
export function usePopover() {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    const onDown = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setOpen(false);
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);
  return { open, setOpen, ref };
}
