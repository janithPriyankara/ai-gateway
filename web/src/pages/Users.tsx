import { useState, type FormEvent } from 'react';
import * as api from '../api';
import type { AdminKey, Role, User } from '../api';
import { useSession } from '../session';
import { Confirm, Dialog, Empty, ErrorNotice, Loading, Notice, PageHead, Secret, formatTime, isZero, useLoad } from '../components/ui';
import { IconPlus } from '../icons';

const ROLES: Role[] = ['owner', 'admin', 'member', 'viewer'];
const label = (r: string) => r.charAt(0).toUpperCase() + r.slice(1);

export default function UsersPage() {
  const { me, can } = useSession();
  const isOwner = can('owner');
  const users = useLoad(() => (can('admin') ? api.listUsers() : Promise.resolve([] as User[])));
  const keys = useLoad(() => (isOwner ? api.listKeys() : Promise.resolve([] as AdminKey[])));
  const [err, setErr] = useState<unknown>(null);
  const [inviting, setInviting] = useState(false);
  const [creatingKey, setCreatingKey] = useState(false);
  const [revoking, setRevoking] = useState<AdminKey | null>(null);
  const [removing, setRemoving] = useState<User | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  if (!can('admin')) {
    return (
      <>
        <PageHead title="Users" />
        <Notice kind="info">Only admins and owners can see users.</Notice>
      </>
    );
  }

  const changeRole = async (u: User, role: Role) => {
    setErr(null);
    setMsg(null);
    try {
      await api.setUserRole(u.id, role);
      setMsg(`${u.name} is now ${label(role).toLowerCase()}.`);
      await users.reload();
    } catch (e) {
      setErr(e);
      await users.reload();
    }
  };

  return (
    <>
      <PageHead
        title="Users"
        sub="People who can sign in to this dashboard, and API keys for automation."
        actions={isOwner && <button type="button" className="primary" onClick={() => setInviting(true)}><IconPlus size={16} /> Invite user</button>}
      />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorNotice error={users.error ?? err} onDismiss={err ? () => setErr(null) : undefined} />
      <section className="card" aria-labelledby="users-h">
        <h2 id="users-h">Users</h2>
        {users.loading && !users.data ? <Loading /> : (
          <div className="table-wrap">
            <table>
              <thead><tr><th>Name</th><th>Role</th><th>Joined</th><th><span className="sr-only">Actions</span></th></tr></thead>
              <tbody>
                {(users.data ?? []).map((u) => (
                  <tr key={u.id} data-testid={`user-row-${u.name}`}>
                    <td><strong>{u.name}</strong>{u.id === me.user_id && <span className="muted small"> (you)</span>}</td>
                    <td>
                      {isOwner && u.id !== me.user_id ? (
                        <select className="compact" value={u.role} aria-label={`Role for ${u.name}`} onChange={(e) => void changeRole(u, e.target.value as Role)}>
                          {ROLES.map((r) => <option key={r} value={r}>{label(r)}</option>)}
                        </select>
                      ) : (
                        <span className="badge">{label(u.role)}</span>
                      )}
                    </td>
                    <td>{formatTime(u.created_at)}</td>
                    <td className="actions">
                      {isOwner && u.id !== me.user_id && (
                        <button type="button" className="sm danger" onClick={() => setRemoving(u)} aria-label={`Remove ${u.name}`}>Remove</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!isOwner && <p className="muted small" style={{ marginTop: 10, marginBottom: 0 }}>Only the owner can invite users or change roles.</p>}
      </section>

      {isOwner && (
        <section className="card" aria-labelledby="keys-h">
          <div className="row" style={{ marginBottom: 12 }}>
            <h2 id="keys-h" style={{ margin: 0 }}>Admin API keys</h2>
            <span className="spacer" />
            <button type="button" className="sm" onClick={() => setCreatingKey(true)}><IconPlus size={14} /> Create API key</button>
          </div>
          <ErrorNotice error={keys.error} />
          {keys.loading && !keys.data ? <Loading /> : (keys.data ?? []).length === 0 ? (
            <Empty title="No API keys">Create a key to manage the gateway from scripts or CI.</Empty>
          ) : (
            <div className="table-wrap">
              <table>
                <thead><tr><th>Name</th><th>Prefix</th><th>Created</th><th>Status</th><th><span className="sr-only">Actions</span></th></tr></thead>
                <tbody>
                  {(keys.data ?? []).map((k) => {
                    const revoked = !isZero(k.revoked_at);
                    return (
                      <tr key={k.id} data-testid={`key-row-${k.name}`}>
                        <td>{k.name}</td>
                        <td><code>{k.prefix}</code></td>
                        <td>{formatTime(k.created_at)}</td>
                        <td>{revoked ? <span className="badge danger">Revoked</span> : <span className="badge ok">Active</span>}</td>
                        <td className="actions">
                          {!revoked && <button type="button" className="sm danger" onClick={() => setRevoking(k)} aria-label={`Revoke key ${k.name}`}>Revoke</button>}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {inviting && <InviteDialog onClose={() => setInviting(false)} />}
      {creatingKey && <KeyDialog onClose={() => { setCreatingKey(false); void keys.reload(); }} />}
      {revoking && (
        <Confirm title={`Revoke ${revoking.name}?`} body={<p>Scripts using this key will stop working immediately.</p>} confirmLabel="Revoke key"
          onClose={() => setRevoking(null)} onConfirm={async () => { await api.revokeKey(revoking.id); await keys.reload(); }} />
      )}
      {removing && (
        <Confirm title={`Remove ${removing.name}?`} body={<p>They will be signed out and lose access. Their AI tool tokens stop working.</p>} confirmLabel="Remove user"
          onClose={() => setRemoving(null)} onConfirm={async () => { await api.deleteUser(removing.id); await users.reload(); }} />
      )}
    </>
  );
}

function InviteDialog({ onClose }: { onClose: () => void }) {
  const [role, setRole] = useState<Role>('member');
  const [url, setUrl] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      setUrl((await api.createInvite(role)).url);
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title="Invite user" onClose={onClose} footer={url ? <button type="button" className="primary" onClick={onClose}>Done</button> : undefined}>
      {url ? (
        <>
          <p>Send this one-time link to the person you are inviting. They will register a passkey and join as <strong>{role}</strong>.</p>
          <Secret value={url} label="Invite link" />
        </>
      ) : (
        <form onSubmit={submit}>
          <ErrorNotice error={err} />
          <div className="field">
            <label htmlFor="inv-role">Role</label>
            <select id="inv-role" value={role} onChange={(e) => setRole(e.target.value as Role)}>
              <option value="viewer">Viewer: sees everything, changes nothing</option>
              <option value="member">Member: connects own AI tools and credentials</option>
              <option value="admin">Admin: manages servers, profiles and approvals</option>
              <option value="owner">Owner: full control</option>
            </select>
          </div>
          <div className="dialog-foot">
            <button type="button" onClick={onClose}>Cancel</button>
            <button type="submit" className="primary" disabled={busy}>Create invite link</button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function KeyDialog({ onClose }: { onClose: () => void }) {
  const [name, setName] = useState('');
  const [key, setKey] = useState<string | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      setKey((await api.createKey(name.trim())).key);
    } catch (e2) {
      setErr(e2);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog title="Create API key" onClose={onClose} footer={key ? <button type="button" className="primary" onClick={onClose}>Done</button> : undefined}>
      {key ? (
        <>
          <div className="notice warn" role="status"><span className="grow">Copy this key now. It is shown only once.</span></div>
          <Secret value={key} label="API key" />
          <p className="muted small" style={{ marginTop: 10 }}>Use it as <code>Authorization: Bearer …</code> with the Admin API.</p>
        </>
      ) : (
        <form onSubmit={submit}>
          <ErrorNotice error={err} />
          <div className="field">
            <label htmlFor="key-name">Name</label>
            <input id="key-name" type="text" value={name} onChange={(e) => setName(e.target.value)} required placeholder="CI deploy" />
          </div>
          <div className="dialog-foot">
            <button type="button" onClick={onClose}>Cancel</button>
            <button type="submit" className="primary" disabled={busy}>Create key</button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
