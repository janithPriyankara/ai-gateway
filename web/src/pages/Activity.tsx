import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import * as api from '../api';
import type { AuditEvent, ChainResult } from '../api';
import { useLiveRefresh } from '../session';
import { DecisionBadge, Empty, ErrorNotice, Loading, Notice, PageHead, formatTime, useLoad } from '../components/ui';

const PAGE = 50;

export default function ActivityPage() {
  const [params, setParams] = useSearchParams();
  const server = params.get('server') ?? '';
  const client = params.get('client') ?? '';
  const decision = params.get('decision') ?? '';
  const servers = useLoad(api.listServers);
  const clients = useLoad(api.listClients);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [more, setMore] = useState(false);
  const [loading, setLoading] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [verify, setVerify] = useState<ChainResult | null>(null);
  const [verifying, setVerifying] = useState(false);
  const [newCount, setNewCount] = useState(0);

  const load = async () => {
    setErr(null);
    try {
      const evs = await api.queryAudit({ server, client, decision, limit: PAGE });
      setEvents(evs);
      setMore(evs.length === PAGE);
      setNewCount(0);
    } catch (e) {
      setErr(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    setLoading(true);
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [server, client, decision]);

  useLiveRefresh(['audit.event'], () => setNewCount((n) => n + 1));

  const loadMore = async () => {
    const last = events[events.length - 1];
    if (!last) return;
    setLoadingMore(true);
    setErr(null);
    try {
      const evs = await api.queryAudit({ server, client, decision, before: last.id, limit: PAGE });
      setEvents((cur) => [...cur, ...evs]);
      setMore(evs.length === PAGE);
    } catch (e) {
      setErr(e);
    } finally {
      setLoadingMore(false);
    }
  };

  const runVerify = async () => {
    setVerifying(true);
    setVerify(null);
    setErr(null);
    try {
      setVerify(await api.verifyAudit());
    } catch (e) {
      setErr(e);
    } finally {
      setVerifying(false);
    }
  };

  const setFilter = (k: string, v: string) => {
    const p = new URLSearchParams(params);
    if (v) p.set(k, v);
    else p.delete(k);
    setParams(p, { replace: true });
  };

  return (
    <>
      <PageHead
        title="Activity"
        sub="Every tool call and admin change, in a tamper-evident log."
        actions={<button type="button" onClick={runVerify} disabled={verifying}>{verifying ? 'Verifying…' : 'Verify chain'}</button>}
      />
      {verify && (
        <Notice kind={verify.ok ? 'success' : 'error'}>
          <span data-testid="verify-result">
            {verify.ok
              ? `Chain intact: ${verify.checked} events checked, no tampering found.`
              : `Chain broken at event ${verify.broken_at ?? '?'} after ${verify.checked} events. The log may have been modified.`}
          </span>
        </Notice>
      )}
      <ErrorNotice error={err} onDismiss={() => setErr(null)} />
      <form className="filters" aria-label="Filters" onSubmit={(e) => e.preventDefault()}>
        <div className="field">
          <label htmlFor="f-server">Server</label>
          <select id="f-server" value={server} onChange={(e) => setFilter('server', e.target.value)}>
            <option value="">All servers</option>
            {(servers.data ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-client">AI tool</label>
          <select id="f-client" value={client} onChange={(e) => setFilter('client', e.target.value)}>
            <option value="">All AI tools</option>
            {(clients.data ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-decision">Decision</label>
          <select id="f-decision" value={decision} onChange={(e) => setFilter('decision', e.target.value)}>
            <option value="">All decisions</option>
            <option value="allow">Allowed</option>
            <option value="ask">Asked</option>
            <option value="deny">Denied</option>
          </select>
        </div>
        {newCount > 0 && (
          <button type="button" className="sm" onClick={() => void load()} style={{ marginBottom: 2 }}>
            Show {newCount} new event{newCount === 1 ? '' : 's'}
          </button>
        )}
      </form>
      {loading ? <Loading /> : events.length === 0 ? (
        <div className="card"><Empty title="No activity yet">Calls from AI tools and changes made here will show up in this log.</Empty></div>
      ) : (
        <>
          <div className="table-wrap">
            <table aria-label="Audit events">
              <thead>
                <tr><th>Time</th><th>Kind</th><th>Tool</th><th>AI tool</th><th>Decision</th><th>Status</th><th>Latency</th><th>Summary</th></tr>
              </thead>
              <tbody>
                {events.map((e) => (
                  <tr key={e.id} data-testid="audit-row">
                    <td style={{ whiteSpace: 'nowrap' }}>{formatTime(e.time, { seconds: true })}</td>
                    <td>{e.kind}</td>
                    <td>{e.tool ? <code>{e.tool}</code> : <span className="muted">-</span>}</td>
                    <td>{clientName(clients.data, e.client_id)}</td>
                    <td>{e.decision && e.decision !== '-' ? <DecisionBadge decision={e.decision} /> : <span className="muted">-</span>}</td>
                    <td>{e.status}</td>
                    <td>{e.kind === 'call' ? `${e.latency_ms} ms` : ''}</td>
                    <td style={{ maxWidth: 360 }}><div className="desc small clamp-2" style={{ wordBreak: 'break-word' }} title={e.summary}>{e.summary}</div></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {more && (
            <div className="row" style={{ justifyContent: 'center', marginTop: 14 }}>
              <button type="button" onClick={loadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load more'}</button>
            </div>
          )}
        </>
      )}
    </>
  );
}

function clientName(list: api.Client[] | null, id: string): string {
  if (!id) return '-';
  return list?.find((c) => c.id === id)?.name ?? id;
}
