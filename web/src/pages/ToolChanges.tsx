import { useState } from 'react';
import * as api from '../api';
import type { ToolPin } from '../api';
import { wordDiff } from '../diff';
import { useLiveRefresh, useSession } from '../session';
import { Empty, ErrorNotice, Loading, Notice, PageHead, formatTime, useLoad } from '../components/ui';

export default function ToolChangesPage() {
  const { can } = useSession();
  const changes = useLoad(api.listPinChanges);
  useLiveRefresh(['config.changed'], () => void changes.reload());
  const [err, setErr] = useState<unknown>(null);
  const [done, setDone] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const act = async (p: ToolPin, accept: boolean) => {
    const k = p.server_id + '/' + p.tool;
    setBusy(k);
    setErr(null);
    setDone(null);
    try {
      if (accept) await api.acceptPin(p.server_id, p.tool);
      else await api.rejectPin(p.server_id, p.tool);
      setDone(accept ? `Accepted the new definition of ${p.tool}. The tool is available again.` : `Rejected the change to ${p.tool}. It stays paused.`);
      await changes.reload();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(null);
    }
  };

  const list = changes.data ?? [];
  return (
    <>
      <PageHead title="Tool changes" sub="When a server changes a tool's description or inputs, the tool is paused until someone reviews the change. This protects against tool poisoning." />
      {done && <Notice kind="success">{done}</Notice>}
      <ErrorNotice error={changes.error ?? err} onDismiss={err ? () => setErr(null) : undefined} />
      {changes.loading && !changes.data ? <Loading /> : list.length === 0 ? (
        <div className="card"><Empty title="No changes to review">All tool definitions match what was approved.</Empty></div>
      ) : (
        <div className="stack">
          {list.map((p) => {
            const k = p.server_id + '/' + p.tool;
            const parts = wordDiff(p.old_description ?? '', p.new_description ?? '');
            const schemaChanged = (p.old_schema ?? '') !== (p.new_schema ?? '');
            return (
              <section key={k} className="card" data-testid={`change-${p.server_id}-${p.tool}`} aria-label={`Change to ${p.tool}`}>
                <div className="row" style={{ marginBottom: 10 }}>
                  <h2 style={{ margin: 0 }}><code>{p.tool}</code></h2>
                  <span className="badge">{p.server_id}</span>
                  <span className="badge danger">Paused</span>
                  <span className="spacer" />
                  <span className="muted small">detected {formatTime(p.updated_at)}</span>
                </div>
                <h3>Description</h3>
                <div className="diff" data-testid="diff" aria-label="Description changes">
                  {parts.length === 0 ? <span className="muted">(empty)</span> : parts.map((d, i) =>
                    d.type === 'add' ? <ins key={i}>{d.text}</ins> : d.type === 'del' ? <del key={i}>{d.text}</del> : <span key={i}>{d.text}</span>,
                  )}
                </div>
                <p className="muted small" style={{ marginTop: 6 }}>
                  <span className="sr-only">Legend: </span><del className="diff-legend">removed</del> <ins className="diff-legend">added</ins>
                </p>
                {schemaChanged && (
                  <details style={{ marginTop: 8 }}>
                    <summary>Input schema changed</summary>
                    <div className="diff-cols" style={{ marginTop: 8 }}>
                      <div><div className="muted small">Before</div><pre className="snippet">{p.old_schema || '(none)'}</pre></div>
                      <div><div className="muted small">After</div><pre className="snippet">{p.new_schema || '(none)'}</pre></div>
                    </div>
                  </details>
                )}
                {can('admin') && (
                  <div className="row end" style={{ marginTop: 12 }}>
                    <button type="button" className="danger" disabled={busy === k} onClick={() => void act(p, false)} aria-label={`Reject change to ${p.tool}`}>Reject</button>
                    <button type="button" className="primary" disabled={busy === k} onClick={() => void act(p, true)} aria-label={`Accept change to ${p.tool}`}>Accept</button>
                  </div>
                )}
              </section>
            );
          })}
        </div>
      )}
    </>
  );
}
