import { useState } from 'react';
import * as api from '../api';
import type { Approval } from '../api';
import { useLiveRefresh, useSession } from '../session';
import { Empty, ErrorNotice, Loading, PageHead, formatTime, relativeTime, useLoad } from '../components/ui';

export default function ApprovalsPage() {
  const { me, can } = useSession();
  const pending = useLoad(() => api.listApprovals('pending'));
  const recent = useLoad(() => api.listApprovals());
  useLiveRefresh(['approval.created', 'approval.decided'], () => {
    void pending.reload();
    void recent.reload();
  });
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const canDecide = (a: Approval) => can('member') && (a.user_id === me.user_id || can('admin'));

  const decide = async (a: Approval, approve: boolean, always = false) => {
    setBusy(a.id);
    setErr(null);
    try {
      await api.decideApproval(a.id, approve, always);
      pending.setData((cur) => (cur ?? []).filter((x) => x.id !== a.id));
      void recent.reload();
    } catch (e) {
      setErr(e);
      void pending.reload();
    } finally {
      setBusy(null);
    }
  };

  const list = pending.data ?? [];
  const decided = (recent.data ?? []).filter((a) => a.status !== 'pending').slice(0, 20);
  return (
    <>
      <PageHead title="Approvals" sub="Calls that matched an “ask” rule wait here for a human decision. New requests appear automatically." />
      <ErrorNotice error={pending.error ?? err} onDismiss={err ? () => setErr(null) : undefined} />
      <section className="card" aria-labelledby="pending-h">
        <h2 id="pending-h">Waiting for a decision</h2>
        {pending.loading && !pending.data ? <Loading /> : list.length === 0 ? (
          <Empty title="Nothing is waiting">When an AI tool calls a tool covered by an “ask” rule, it pauses here until someone approves or denies it.</Empty>
        ) : (
          <ul className="list" data-testid="pending-list">
            {list.map((a) => (
              <li key={a.id} data-testid={`approval-${a.id}`}>
                <div style={{ flex: 1, minWidth: 220 }}>
                  <div><strong>{a.client_name || a.client_id}</strong> wants to run <code>{a.tool}</code></div>
                  {a.summary && <div className="muted small mono" style={{ wordBreak: 'break-all' }}>{a.summary}</div>}
                  <div className="muted small">Profile {a.profile} · requested {relativeTime(a.created_at)} · expires {relativeTime(a.expires_at)}</div>
                </div>
                {canDecide(a) && (
                  <div className="row">
                    <button type="button" className="danger" disabled={busy === a.id} onClick={() => void decide(a, false)}
                      aria-label={`Deny ${a.tool}`}>Deny</button>
                    <button type="button" className="primary" disabled={busy === a.id} onClick={() => void decide(a, true)}
                      aria-label={`Approve ${a.tool}`}>Approve</button>
                    {can('admin') && (
                      <button type="button" disabled={busy === a.id} onClick={() => void decide(a, true, true)}
                        title="Approve and add an allow rule for this tool" aria-label={`Always allow ${a.tool}`}>Always allow</button>
                    )}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="card" aria-labelledby="recent-h">
        <h2 id="recent-h">Recent decisions</h2>
        {decided.length === 0 ? <p className="muted" style={{ margin: 0 }}>No decisions yet.</p> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Tool</th><th>AI tool</th><th>Result</th><th>By</th><th>When</th></tr></thead>
              <tbody>
                {decided.map((a) => (
                  <tr key={a.id}>
                    <td><code>{a.tool}</code></td>
                    <td>{a.client_name}</td>
                    <td><span className={`badge ${a.status === 'approved' ? 'ok' : a.status === 'denied' ? 'danger' : ''}`}>{a.status}</span></td>
                    <td>{a.decided_by || '-'}</td>
                    <td>{formatTime(a.decided_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
