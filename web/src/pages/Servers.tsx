import { useState } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import * as api from '../api';
import type { Server } from '../api';
import { useLiveRefresh, useSession } from '../session';
import { Confirm, Empty, ErrorNotice, HealthBadge, Loading, Notice, PageHead, effectiveHealth, useLoad } from '../components/ui';
import { ServerDialog } from '../components/ServerForm';
import { IconPlus } from '../icons';

interface Row extends Server {
  toolCount: number | null;
  creds: api.CredentialInfo[] | null;
}

async function load(): Promise<Row[]> {
  const servers = await api.listServers();
  const [counts, creds] = await Promise.all([
    Promise.all(servers.map((s) => api.listServerTools(s.id).then((t) => t.length).catch(() => null))),
    Promise.all(servers.map((s) => (s.auth_kind === 'none' ? Promise.resolve([]) : api.listCredentials(s.id).catch(() => null)))),
  ]);
  return servers.map((s, i) => ({ ...s, toolCount: counts[i], creds: creds[i] }));
}

export default function ServersPage() {
  const { can, me } = useSession();
  const isAdmin = can('admin');
  const nav = useNavigate();
  const [params] = useSearchParams();
  const oauthError = params.get('oauth_error');
  const { data, error, loading, reload } = useLoad(load);
  useLiveRefresh(['config.changed', 'server.health'], () => void reload());
  const [adding, setAdding] = useState(false);
  const [editing, setEditing] = useState<Server | null>(null);
  const [deleting, setDeleting] = useState<Server | null>(null);

  return (
    <>
      <PageHead
        title="Servers"
        sub="Upstream MCP servers your AI tools reach through the gateway."
        actions={isAdmin && (
          <button type="button" className="primary" onClick={() => setAdding(true)}>
            <IconPlus size={16} /> Add server
          </button>
        )}
      />
      {oauthError && <Notice kind="error">Connecting failed: {oauthError}</Notice>}
      <ErrorNotice error={error} />
      {loading && !data ? (
        <Loading />
      ) : data && data.length === 0 ? (
        <div className="card">
          <Empty
            title="No servers yet"
            action={isAdmin && (
              <button type="button" className="primary" onClick={() => setAdding(true)}>
                <IconPlus size={16} /> Add your first server
              </button>
            )}
          >
            {isAdmin ? 'Pick one from the catalog (GitHub, Notion, Linear…) or add any MCP server by URL or command.' : 'An admin has not added any servers yet.'}
          </Empty>
        </div>
      ) : data ? (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Transport</th>
                <th>Health</th>
                <th>Tools</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {data.map((s) => (
                <tr key={s.id} data-testid={`server-row-${s.id}`}>
                  <td>
                    <Link to={`/servers/${encodeURIComponent(s.id)}`}><strong>{s.name}</strong></Link>
                    <div className="muted small"><code>{s.prefix}__*</code>{!s.enabled && ' · disabled'}</div>
                  </td>
                  <td><span className="badge">{s.transport}</span></td>
                  <td><HealthBadge health={effectiveHealth(s, s.creds, me.user_id)} /></td>
                  <td>{s.toolCount ?? '-'}</td>
                  <td className="actions">
                    {isAdmin && (
                      <div className="row end">
                        <button type="button" className="sm" onClick={() => setEditing(s)} aria-label={`Edit ${s.name}`}>Edit</button>
                        <button type="button" className="sm danger" onClick={() => setDeleting(s)} aria-label={`Delete ${s.name}`}>Delete</button>
                      </div>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
      {adding && (
        <ServerDialog onClose={() => setAdding(false)} onSaved={(s) => { setAdding(false); nav(`/servers/${encodeURIComponent(s.id)}`); }} />
      )}
      {editing && (
        <ServerDialog initial={editing} onClose={() => setEditing(null)} onSaved={() => { setEditing(null); void reload(); }} />
      )}
      {deleting && (
        <Confirm
          title={`Delete ${deleting.name}?`}
          body={<p>The server, its tool pins and every stored credential for it will be removed. AI tools lose access immediately.</p>}
          confirmLabel="Delete server"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await api.deleteServer(deleting.id);
            await reload();
          }}
        />
      )}
    </>
  );
}
