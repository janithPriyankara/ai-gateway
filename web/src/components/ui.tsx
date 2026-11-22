import { useCallback, useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { errorMessage, isZeroTime } from '../api';
import { IconAlert, IconCopy, IconX } from '../icons';

export function ErrorNotice({ error, onDismiss }: { error: unknown; onDismiss?: () => void }) {
  if (!error) return null;
  return (
    <div className="notice error" role="alert">
      <IconAlert />
      <span className="grow">{errorMessage(error)}</span>
      {onDismiss && (
        <button type="button" className="ghost icon sm" onClick={onDismiss} aria-label="Dismiss">
          <IconX size={14} />
        </button>
      )}
    </div>
  );
}

export function Notice({ kind, children }: { kind: 'success' | 'info' | 'warn' | 'error'; children: ReactNode }) {
  return (
    <div className={`notice ${kind}`} role={kind === 'error' ? 'alert' : 'status'}>
      <span className="grow">{children}</span>
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="loading" role="status">
      <span className="spinner" aria-hidden="true" /> {label}
    </div>
  );
}

export function Empty({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return (
    <div className="empty">
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action && <div className="row">{action}</div>}
    </div>
  );
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p className="muted">{sub}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

/** Accessible modal dialog: focus is trapped inside, Escape closes, focus returns on close. */
export function Dialog({
  title,
  onClose,
  children,
  footer,
  wide,
}: {
  title: string;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const titleId = useId();
  useEffect(() => {
    const prev = document.activeElement as HTMLElement | null;
    const el = ref.current;
    const first = el?.querySelector<HTMLElement>('[autofocus], input, select, textarea, button:not(.dialog-close)');
    (first ?? el)?.focus();
    return () => prev?.focus?.();
  }, []);
  const onKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Escape') {
      e.stopPropagation();
      onClose();
      return;
    }
    if (e.key !== 'Tab' || !ref.current) return;
    const items = Array.from(
      ref.current.querySelectorAll<HTMLElement>('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'),
    );
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  };
  return (
    <div className="dialog-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className={`dialog${wide ? ' wide' : ''}`} role="dialog" aria-modal="true" aria-labelledby={titleId} ref={ref}
        tabIndex={-1} onKeyDown={onKeyDown}>
        <div className="dialog-head">
          <h2 id={titleId}>{title}</h2>
          <button type="button" className="ghost icon dialog-close" onClick={onClose} aria-label="Close">
            <IconX size={16} />
          </button>
        </div>
        {children}
        {footer && <div className="dialog-foot">{footer}</div>}
      </div>
    </div>
  );
}

/** Confirmation dialog for destructive actions. */
export function Confirm({
  title,
  body,
  confirmLabel,
  onConfirm,
  onClose,
}: {
  title: string;
  body: ReactNode;
  confirmLabel: string;
  onConfirm: () => Promise<void> | void;
  onClose: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const go = async () => {
    setBusy(true);
    setErr(null);
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };
  return (
    <Dialog
      title={title}
      onClose={onClose}
      footer={
        <>
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="button" className="danger solid" onClick={go} disabled={busy}>
            {confirmLabel}
          </button>
        </>
      }
    >
      <ErrorNotice error={err} />
      <div>{body}</div>
    </Dialog>
  );
}

export function CopyButton({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
    } catch {
      // Fallback for browsers without clipboard permission.
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand('copy');
      } finally {
        ta.remove();
      }
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  };
  return (
    <button type="button" className="sm" onClick={copy} aria-live="polite">
      <IconCopy size={14} /> {copied ? 'Copied' : label}
    </button>
  );
}

export function Secret({ value, label }: { value: string; label: string }) {
  return (
    <div className="secret">
      <code aria-label={label} data-testid="secret-value">{value}</code>
      <CopyButton text={value} />
    </div>
  );
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
}: {
  tabs: { id: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  label: string;
}) {
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: React.KeyboardEvent, i: number) => {
    let n = -1;
    if (e.key === 'ArrowRight') n = (i + 1) % tabs.length;
    if (e.key === 'ArrowLeft') n = (i - 1 + tabs.length) % tabs.length;
    if (n >= 0) {
      e.preventDefault();
      onChange(tabs[n].id);
      refs.current[n]?.focus();
    }
  };
  return (
    <div className="tabs" role="tablist" aria-label={label}>
      {tabs.map((t, i) => (
        <button key={t.id} type="button" role="tab" aria-selected={value === t.id} tabIndex={value === t.id ? 0 : -1}
          ref={(el) => { refs.current[i] = el; }} onClick={() => onChange(t.id)} onKeyDown={(e) => onKey(e, i)}>
          {t.label}
        </button>
      ))}
    </div>
  );
}

// effectiveHealth folds the caller's credential into the server's health: a server that
// answers but rejects the credential the gateway would use is not "Healthy" (UI-017).
export function effectiveHealth(
  s: { health?: string; auth_kind?: string },
  creds: { user_id: string; status: string }[] | null | undefined,
  userID: string,
): string | undefined {
  const c = creds?.find((x) => x.user_id === userID) ?? creds?.find((x) => x.user_id === '');
  if (c?.status === 'needs_reauth') return s.auth_kind === 'oauth' ? 'needs_reauth' : 'cred_rejected';
  return s.health;
}
export function HealthBadge({ health }: { health?: string }) {
  switch (health) {
    case 'ok':
      return <span className="badge ok"><span className="dot" /> Healthy</span>;
    case 'down':
      return <span className="badge danger"><span className="dot" /> Down</span>;
    case 'needs_reauth':
      return <span className="badge warn"><span className="dot" /> Needs sign-in</span>;
    case 'cred_rejected':
      return <span className="badge warn" title="The server answers, but rejected the stored credential. Save a new one on the server page."><span className="dot" /> Credential rejected</span>;
    default:
      return <span className="badge"><span className="dot" /> Unknown</span>;
  }
}

export function DecisionBadge({ decision }: { decision: string }) {
  const cls = decision === 'allow' ? 'ok' : decision === 'deny' ? 'danger' : decision === 'ask' ? 'warn' : '';
  return <span className={`badge ${cls}`}>{decision || '-'}</span>;
}

export function formatTime(t: string | undefined, opts: { seconds?: boolean } = {}): string {
  if (isZeroTime(t)) return 'Never';
  const d = new Date(t as string);
  if (Number.isNaN(d.getTime())) return '-';
  return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: opts.seconds ? 'medium' : 'short' });
}

export function relativeTime(t: string | undefined): string {
  if (isZeroTime(t)) return 'Never';
  const d = new Date(t as string).getTime();
  const s = Math.round((Date.now() - d) / 1000);
  if (s < 0) {
    const f = -s;
    if (f < 60) return `in ${f}s`;
    if (f < 3600) return `in ${Math.round(f / 60)} min`;
    return `in ${Math.round(f / 3600)} h`;
  }
  if (s < 60) return 'Just now';
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** Loads data with an async function; reload() refetches. */
export function useLoad<T>(fn: () => Promise<T>, deps: unknown[] = []) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const fnRef = useRef(fn);
  fnRef.current = fn;
  const seq = useRef(0);
  const reload = useCallback(async () => {
    const n = ++seq.current;
    try {
      const v = await fnRef.current();
      if (n === seq.current) {
        setData(v);
        setError(null);
      }
    } catch (e) {
      if (n === seq.current) setError(e);
    } finally {
      if (n === seq.current) setLoading(false);
    }
  }, []);
  useEffect(() => {
    setLoading(true);
    void reload();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps);
  return { data, error, loading, reload, setData };
}
export const isZero = isZeroTime;
