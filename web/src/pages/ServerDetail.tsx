import { useState, type FormEvent } from 'react';
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import * as api from '../api';
import type { Credential, CredentialInfo, Server, ToolPin } from '../api';
import { useLiveRefresh, useSession } from '../session';
import { Confirm, Empty, ErrorNotice, HealthBadge, Loading, Notice, PageHead, formatTime, useLoad } from '../components/ui';
import { ServerDialog } from '../components/ServerForm';

export default function ServerDetailPage() {
  const { id = '' } = useParams();
  const [params, setParams] = useSearchParams();
  const nav = useNavigate();
  const { can } = useSession();
  const server = useLoad(() => api.getServer(id), [id]);
  const tools = useLoad(() => api.listServerTools(id), [id]);
  const creds = useLoad(() => api.listCredentials(id), [id]);
  useLiveRefresh(['config.changed', 'server.health'], () => {
    void server.reload();
    void tools.reload();
  });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [actionErr, setActionErr] = useState<unknown>(null);
  const connected = params.get('connected') === '1';

  if (server.loading && !server.data) return <Loading />;
  if (!server.data) {
    return (
      <>
        <PageHead title="Server" />
        <ErrorNotice error={server.error} />
        <Link to="/servers">Back to servers</Link>
      </>
    );
  }
  const s = server.data;

  const test = async () => {
    setTesting(true);
    setTestResult(null);
    setActionErr(null);
    try {
      const r = await api.testServer(s.id);
      setTestResult(r.ok ? { ok: true, text: `Connected. ${r.tools ?? 0} tools found.` } : { ok: false, text: `Connection failed: ${r.error ?? 'unknown error'}` });
      await Promise.all([server.reload(), tools.reload()]);
    } catch (e) {
      setActionErr(e);
    } finally {
      setTesting(false);
    }
  };

  const connect = async () => {
    setActionErr(null);
    try {
      const r = await api.connectServer(s.id);
      window.location.assign(r.authorize_url);
    } catch (e) {
      setActionErr(e);
    }
  };

  return (
    <>
      <p className="small" style={{ marginBottom: 8 }}><Link to="/servers">Servers</Link> /</p>
      <PageHead
        title={s.name}
        sub={<><code>{s.prefix}__*</code> · {s.transport === 'http' ? s.url : [s.command, ...(s.args ?? [])].join(' ')}</>}
        actions={
          <>
            <HealthBadge health={s.health} />
            {can('member') && (
              <button type="button" onClick={test} disabled={testing}>
                {testing ? 'Testing…' : 'Test connection'}
              </button>
            )}
            {can('member') && s.auth_kind === 'oauth' && (
              <button type="button" className="primary" onClick={connect}>Connect</button>
            )}
            {can('admin') && <button type="button" onClick={() => setEditing(true)}>Edit</button>}
            {can('admin') && <button type="button" className="danger" onClick={() => setDeleting(true)}>Delete</button>}
          </>
        }
      />
      {connected && (
        <div className="notice success" role="status">
          <span className="grow">Connected. The gateway stored your OAuth credential for this server.</span>
          <button type="button" className="ghost sm" onClick={() => { params.delete('connected'); setParams(params, { replace: true }); }}>Dismiss</button>
        </div>
      )}
      {testResult && <Notice kind={testResult.ok ? 'success' : 'error'}>{testResult.text}</Notice>}
      <ErrorNotice error={actionErr} onDismiss={() => setActionErr(null)} />

      <section className="card">
        <h2>Tools</h2>
        <ErrorNotice error={tools.error} />
        {tools.loading && !tools.data ? <Loading /> : tools.data && tools.data.length === 0 ? (
          <Empty title="No tools seen yet">
            The gateway records tools the first time it connects. {can('member') ? 'Use Test connection to fetch them now.' : ''}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr><th>Tool</th><th>Access</th><th>Pin</th></tr>
              </thead>
              <tbody>
                {(tools.data ?? []).map((t) => <ToolRow key={t.tool} t={t} />)}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {s.auth_kind !== 'none' && (
        <CredentialCard server={s} creds={creds.data ?? []} credsError={creds.error} onChanged={() => void creds.reload()} />
      )}
      {s.auth_kind === 'oauth' && can('admin') && <OAuthAppCard server={s} />}

      {editing && <ServerDialog initial={s} onClose={() => setEditing(false)} onSaved={() => { setEditing(false); void server.reload(); }} />}
      {deleting && (
        <Confirm
          title={`Delete ${s.name}?`}
          body={<p>The server, its tool pins and every stored credential for it will be removed.</p>}
          confirmLabel="Delete server"
          onClose={() => setDeleting(false)}
          onConfirm={async () => {
            await api.deleteServer(s.id);
            nav('/servers');
          }}
        />
      )}
    </>
  );
}


function ToolRow({ t }: { t: ToolPin }) {
  const pending = !!t.pending_fingerprint;
  return (
    <tr data-testid={`tool-row-${t.tool}`}>
      <td>
        <code>{t.tool}</code>
        {t.description && <div className="desc">{t.description}</div>}
      </td>
      <td>{t.read_only ? <span className="badge ok">Read-only</span> : <span className="badge warn">Write</span>}</td>
      <td>
        {t.status === 'quarantined' ? (
          <span className="badge danger">{pending ? 'Changed: paused' : 'Quarantined'}</span>
        ) : (
          <span className="badge">Pinned</span>
        )}
        {pending && <> <Link to="/tool-changes" className="small">Review</Link></>}
      </td>
    </tr>
  );
}

type CredKind = 'bearer' | 'header' | 'env';

function CredentialCard({
  server,
  creds,
  credsError,
  onChanged,
}: {
  server: Server;
  creds: CredentialInfo[];
  credsError: unknown;
  onChanged: () => void;
}) {
  const { me, can } = useSession();
  const defaultKind: CredKind = server.auth_kind === 'header' ? 'header' : server.auth_kind === 'env' ? 'env' : 'bearer';
  const [kind, setKind] = useState<CredKind>(defaultKind);
  const [scope, setScope] = useState<'me' | 'shared'>('me');
  const [token, setToken] = useState('');
  const [headerName, setHeaderName] = useState('');
  const [headerValue, setHeaderValue] = useState('');
  const [envText, setEnvText] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const [removing, setRemoving] = useState<'me' | 'shared' | null>(null);
  const mine = creds.find((c) => c.user_id === me.user_id);
  const shared = creds.find((c) => c.user_id === '');

  if (server.auth_kind === 'oauth' && !can('member')) return null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setSaved(false);
    let c: Credential;
    if (kind === 'bearer') c = { kind, token };
    else if (kind === 'header') c = { kind, header_name: headerName, header_value: headerValue };
    else {
      const env: Record<string, string> = {};
      for (const line of envText.split('\n')) {
        const t = line.trim();
        if (!t || t.startsWith('#')) continue;
        const i = t.indexOf('=');
        if (i <= 0) {
          setErr(new Error(`Use KEY=value on each line (problem: "${t.slice(0, 40)}").`));
          return;
        }
        env[t.slice(0, i).trim()] = t.slice(i + 1);
      }
      c = { kind, env };
    }
    setBusy(true);
    try {
      await api.setCredential(server.id, scope, c);
      // The value is write-only: clear it from the form and never show it again.
      setToken('');
      setHeaderValue('');
      setEnvText('');
      setSaved(true);
      onChanged();
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" aria-labelledby="cred-h">
      <h2 id="cred-h">Credential</h2>
      <ErrorNotice error={credsError} />
      <ul className="list" style={{ marginBottom: 12 }}>
        <li>
          <span style={{ flex: 1 }}>Your credential</span>
          {mine ? <><span className="badge ok">Set</span><span className="muted small">updated {formatTime(mine.updated_at)}</span></> : <span className="badge">Not set</span>}
          {mine && mine.status === 'needs_reauth' && <span className="badge warn">Needs sign-in</span>}
          {mine && can('member') && <button type="button" className="sm danger" onClick={() => setRemoving('me')}>Remove</button>}
        </li>
        <li>
          <span style={{ flex: 1 }}>Shared credential (used for everyone without their own)</span>
          {shared ? <><span className="badge ok">Set</span><span className="muted small">updated {formatTime(shared.updated_at)}</span></> : <span className="badge">Not set</span>}
          {shared && can('admin') && <button type="button" className="sm danger" onClick={() => setRemoving('shared')}>Remove</button>}
        </li>
      </ul>
      {server.auth_kind !== 'oauth' && can('member') && (
        <form onSubmit={submit} aria-label="Set credential">
          {saved && <Notice kind="success">Credential saved. For your security it will not be shown again.</Notice>}
          <ErrorNotice error={err} />
          <div className="two-col">
            <div className="field">
              <label htmlFor="cred-kind">Type</label>
              <select id="cred-kind" value={kind} onChange={(e) => setKind(e.target.value as CredKind)}>
                <option value="bearer">Bearer token</option>
                <option value="header">Custom header</option>
                <option value="env">Environment variables</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="cred-scope">Who uses it</label>
              <select id="cred-scope" value={scope} onChange={(e) => setScope(e.target.value as 'me' | 'shared')}>
                <option value="me">Only me</option>
                {can('admin') && <option value="shared">Everyone (shared)</option>}
              </select>
            </div>
          </div>
          {kind === 'bearer' && (
            <div className="field">
              <label htmlFor="cred-token">Token</label>
              <input id="cred-token" type="password" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required />
            </div>
          )}
          {kind === 'header' && (
            <div className="two-col">
              <div className="field">
                <label htmlFor="cred-hname">Header name</label>
                <input id="cred-hname" type="text" value={headerName} onChange={(e) => setHeaderName(e.target.value)} placeholder="X-API-Key" required />
              </div>
              <div className="field">
                <label htmlFor="cred-hvalue">Header value</label>
                <input id="cred-hvalue" type="password" value={headerValue} onChange={(e) => setHeaderValue(e.target.value)} autoComplete="off" required />
              </div>
            </div>
          )}
          {kind === 'env' && (
            <div className="field">
              <label htmlFor="cred-env">Variables (KEY=value, one per line)</label>
              <textarea id="cred-env" value={envText} onChange={(e) => setEnvText(e.target.value)} rows={4} spellCheck={false} required />
            </div>
          )}
          <p className="muted small">The value is encrypted and is never displayed again. Saving replaces any existing value.</p>
          <button type="submit" className="primary" disabled={busy}>{mine || shared ? 'Replace credential' : 'Save credential'}</button>
        </form>
      )}
      {removing && (
        <Confirm
          title="Remove credential?"
          body={<p>{removing === 'shared' ? 'Everyone relying on the shared credential will lose access until a new one is set.' : 'Your AI tools will fall back to the shared credential, if any.'}</p>}
          confirmLabel="Remove"
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await api.deleteCredential(server.id, removing);
            onChanged();
          }}
        />
      )}
    </section>
  );
}

function OAuthAppCard({ server }: { server: Server }) {
  const [authURL, setAuthURL] = useState('');
  const [tokenURL, setTokenURL] = useState('');
  const [clientID, setClientID] = useState('');
  const [secret, setSecret] = useState('');
  const [scopes, setScopes] = useState('');
  const [err, setErr] = useState<unknown>(null);
  const [ok, setOk] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setOk(false);
    try {
      await api.setOAuthApp(server.id, {
        auth_url: authURL, token_url: tokenURL, client_id: clientID, client_secret: secret || undefined,
        scopes: scopes.split(/[\s,]+/).filter(Boolean),
      });
      setSecret('');
      setOk(true);
    } catch (e2) {
      setErr(e2);
    }
  };
  return (
    <section className="card">
      <h2>OAuth app</h2>
      <p className="muted small">The OAuth client the gateway uses to connect to {server.name}. Register the redirect URL <code>{window.location.origin}/admin/oauth/callback</code> with the provider.</p>
      {ok && <Notice kind="success">OAuth app saved.</Notice>}
      <ErrorNotice error={err} />
      <form onSubmit={submit} aria-label="OAuth app">
        <div className="two-col">
          <div className="field"><label htmlFor="oa-auth">Authorization URL</label><input id="oa-auth" type="url" value={authURL} onChange={(e) => setAuthURL(e.target.value)} required /></div>
          <div className="field"><label htmlFor="oa-token">Token URL</label><input id="oa-token" type="url" value={tokenURL} onChange={(e) => setTokenURL(e.target.value)} required /></div>
        </div>
        <div className="two-col">
          <div className="field"><label htmlFor="oa-client">Client ID</label><input id="oa-client" type="text" value={clientID} onChange={(e) => setClientID(e.target.value)} required /></div>
          <div className="field"><label htmlFor="oa-secret">Client secret</label><input id="oa-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" /></div>
        </div>
        <div className="field"><label htmlFor="oa-scopes">Scopes</label><input id="oa-scopes" type="text" value={scopes} onChange={(e) => setScopes(e.target.value)} placeholder="read write" /></div>
        <button type="submit">Save OAuth app</button>
      </form>
    </section>
  );
}
