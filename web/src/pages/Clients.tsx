import { useState, type FormEvent } from 'react';
import * as api from '../api';
import type { Client, CreatedClient, Profile, SnippetKey } from '../api';
import { useLiveRefresh, useSession } from '../session';
import { Confirm, CopyButton, Dialog, Empty, ErrorNotice, Loading, PageHead, Secret, Tabs, isZero, relativeTime, useLoad } from '../components/ui';
import { IconPlus } from '../icons';

const SNIPPETS: { id: SnippetKey; label: string }[] = [
  { id: 'claude_code', label: 'Claude Code' },
  { id: 'codex', label: 'Codex' },
  { id: 'cursor', label: 'Cursor' },
  { id: 'generic', label: 'Other' },
];

export default function ClientsPage() {
  const { me, can } = useSession();
  const clients = useLoad(api.listClients);
  const profiles = useLoad(api.listProfiles);
  useLiveRefresh(['config.changed'], () => void clients.reload());
  const [creating, setCreating] = useState(false);
  const [revoking, setRevoking] = useState<Client | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const canCreate = can('member');
  const canManage = (c: Client) => can('member') && (c.user_id === me.user_id || can('admin'));

  const changeProfile = async (c: Client, profile: string) => {
    setErr(null);
    try {
      await api.setClientProfile(c.id, profile);
      await clients.reload();
    } catch (e) {
      setErr(e);
    }
  };

  const list = clients.data ?? [];
  return (
    <>
      <PageHead
        title="AI tools"
        sub="Coding assistants and agents that connect to the gateway. Each one uses a profile that decides what it may do."
        actions={canCreate && (
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            <IconPlus size={16} /> Connect a tool
          </button>
        )}
      />
      <ErrorNotice error={clients.error ?? err} onDismiss={err ? () => setErr(null) : undefined} />
      {clients.loading && !clients.data ? (
        <Loading />
      ) : list.length === 0 ? (
        <div className="card">
          <Empty title="No AI tools connected" action={canCreate && (
            <button type="button" className="primary" onClick={() => setCreating(true)}>
              <IconPlus size={16} /> Connect your first tool
            </button>
          )}>
            Create a token for Claude Code, Codex, Cursor or any MCP client. Tools that support OAuth can also sign in on their own.
          </Empty>
        </div>
      ) : (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Name</th>
                <th>Profile</th>
                <th>Kind</th>
                <th>Last seen</th>
                <th>Calls</th>
                <th>Status</th>
                <th><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {list.map((c) => {
                const revoked = !isZero(c.revoked_at);
                return (
                  <tr key={c.id} data-testid={`client-row-${c.name}`}>
                    <td>
                      <strong>{c.name}</strong>
                      {c.prefix && <div className="muted small"><code>{c.prefix}…</code></div>}
                    </td>
                    <td>
                      {canManage(c) && !revoked && profiles.data ? (
                        <select className="compact" aria-label={`Profile for ${c.name}`} value={c.profile} onChange={(e) => void changeProfile(c, e.target.value)}>
                          {profiles.data.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
                          {!profiles.data.some((p) => p.name === c.profile) && <option value={c.profile}>{c.profile}</option>}
                        </select>
                      ) : (
                        <span className="badge">{c.profile}</span>
                      )}
                    </td>
                    <td>{c.kind === 'oauth' ? 'OAuth' : 'Token'}</td>
                    <td>{relativeTime(c.last_seen_at)}</td>
                    <td>{(c.calls ?? 0).toLocaleString()}</td>
                    <td>{revoked ? <span className="badge danger">Revoked</span> : <span className="badge ok">Active</span>}</td>
                    <td className="actions">
                      {canManage(c) && !revoked && (
                        <button type="button" className="sm danger" onClick={() => setRevoking(c)} aria-label={`Revoke ${c.name}`}>Revoke</button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {creating && (
        <ConnectDialog profiles={profiles.data ?? []} onClose={() => { setCreating(false); void clients.reload(); }} />
      )}
      {revoking && (
        <Confirm
          title={`Revoke ${revoking.name}?`}
          body={<p>The tool's token stops working immediately. This cannot be undone; you can connect it again with a new token.</p>}
          confirmLabel="Revoke"
          onClose={() => setRevoking(null)}
          onConfirm={async () => {
            await api.revokeClient(revoking.id);
            await clients.reload();
          }}
        />
      )}
    </>
  );
}

function ConnectDialog({ profiles, onClose }: { profiles: Profile[]; onClose: () => void }) {
  const [name, setName] = useState('');
  const [profile, setProfile] = useState(profiles.find((p) => p.name === 'default')?.name ?? profiles[0]?.name ?? '');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [created, setCreated] = useState<CreatedClient | null>(null);
  const [tab, setTab] = useState<SnippetKey>('claude_code');

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      setCreated(await api.createClient(name.trim(), profile));
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };

  if (created) {
    return (
      <Dialog title={`${created.client.name} is ready`} onClose={onClose} wide
        footer={<button type="button" className="primary" onClick={onClose}>Done</button>}>
        <div className="notice warn" role="status">
          <span className="grow">Copy this token now. It is shown only once and cannot be recovered.</span>
        </div>
        <div className="field">
          <label>Token</label>
          <Secret value={created.token} label="Token" />
        </div>
        <h3 style={{ marginTop: 18 }}>Add it to your tool</h3>
        <Tabs label="Snippets" tabs={SNIPPETS} value={tab} onChange={setTab} />
        <div role="tabpanel" aria-label={SNIPPETS.find((s) => s.id === tab)?.label}>
          <pre className="snippet" data-testid="snippet">{created.snippets[tab] ?? ''}</pre>
          <div className="row" style={{ marginTop: 8 }}>
            <CopyButton text={created.snippets[tab] ?? ''} label="Copy snippet" />
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog title="Connect a tool" onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorNotice error={err} />
        {profiles.length === 0 && <div className="notice warn"><span className="grow">Create a profile first: it decides what the tool may do.</span></div>}
        <div className="field">
          <label htmlFor="cl-name">Name</label>
          <input id="cl-name" type="text" value={name} onChange={(e) => setName(e.target.value)} placeholder="Claude Code on my laptop" required maxLength={80} />
        </div>
        <div className="field">
          <label htmlFor="cl-profile">Profile</label>
          <select id="cl-profile" value={profile} onChange={(e) => setProfile(e.target.value)} required>
            {profiles.map((p) => <option key={p.name} value={p.name}>{p.name}</option>)}
          </select>
        </div>
        <div className="dialog-foot">
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="submit" className="primary" disabled={busy || !profile}>Create token</button>
        </div>
      </form>
    </Dialog>
  );
}
