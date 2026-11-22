import { Link } from 'react-router-dom';
import * as api from '../api';
import { useLiveRefresh, useSession } from '../session';
import { Empty, ErrorNotice, Loading, PageHead, useLoad } from '../components/ui';
import { IconChevron } from '../icons';

export default function OverviewPage() {
  const { me, can } = useSession();
  const { data, error, loading, reload } = useLoad(api.getOverview);
  useLiveRefresh(['approval.created', 'approval.decided', 'config.changed', 'server.health', 'audit.event'], () => void reload());

  const items: { key: string; text: string; to: string }[] = [];
  if (data) {
    if (data.pending_approvals > 0)
      items.push({ key: 'ap', to: '/approvals', text: `${data.pending_approvals} pending approval${data.pending_approvals === 1 ? '' : 's'}` });
    if (data.pin_changes > 0)
      items.push({ key: 'pc', to: '/tool-changes', text: `${data.pin_changes} tool change${data.pin_changes === 1 ? '' : 's'} to review` });
    for (const s of data.needs_reauth ?? []) items.push({ key: 'ra-' + s, to: `/servers/${encodeURIComponent(s)}`, text: `Server ${s} needs you to sign in again` });
    for (const s of data.servers_down ?? [])
      if (!(data.needs_reauth ?? []).includes(s)) items.push({ key: 'dn-' + s, to: `/servers/${encodeURIComponent(s)}`, text: `Server ${s} is not responding` });
  }

  return (
    <>
      <PageHead title="Overview" sub={`Welcome back, ${me.name}.`} />
      <ErrorNotice error={error} />
      {loading && !data ? (
        <Loading />
      ) : data ? (
        <>
          <section className="grid-metrics" aria-label="Metrics">
            <Metric label="Servers" value={data.servers} to="/servers" testId="metric-servers" />
            <Metric label="AI tools" value={data.clients} to="/clients" testId="metric-clients" />
            <Metric label="Calls today" value={data.calls_today} to="/activity" testId="metric-calls" />
            <Metric label="Blocked today" value={data.blocked_today} to="/activity?decision=deny" testId="metric-blocked" />
          </section>
          <section className="card" aria-labelledby="attention-h">
            <h2 id="attention-h">Needs your attention</h2>
            {items.length === 0 ? (
              data.servers === 0 ? (
                <Empty title="Nothing here yet" action={can('admin') ? <Link className="btn primary" to="/servers">Add your first server</Link> : undefined}>
                  Add an MCP server, then connect an AI tool to start routing calls through the gateway.
                </Empty>
              ) : (
                <p className="muted" style={{ margin: 0 }}>All clear. No approvals, tool changes or sign-ins are waiting.</p>
              )
            ) : (
              <ul className="list" data-testid="attention-list">
                {items.map((i) => (
                  <li key={i.key}>
                    <Link to={i.to} className="row" style={{ flex: 1 }}>
                      <span style={{ flex: 1 }}>{i.text}</span>
                      <IconChevron size={16} />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
          <section className="card">
            <h2>Key protection</h2>
            <p className="muted" style={{ margin: 0 }}>
              Credentials are encrypted with the <strong>{data.key_provider.name}</strong> key provider ({data.key_provider.strength}).{' '}
              <Link to="/security">Security settings</Link>
            </p>
          </section>
        </>
      ) : null}
    </>
  );
}

function Metric({ label, value, to, testId }: { label: string; value: number; to: string; testId: string }) {
  return (
    <Link to={to} className="metric" data-testid={testId} style={{ color: 'inherit', textDecoration: 'none' }}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
    </Link>
  );
}
