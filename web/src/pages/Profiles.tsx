import { useEffect, useMemo, useState, type FormEvent } from 'react';
import * as api from '../api';
import type { Action, Decision, Profile, Rule, Server, When } from '../api';
import { useLiveRefresh, useSession } from '../session';
import { Confirm, Dialog, Empty, ErrorNotice, Loading, Notice, PageHead, useLoad } from '../components/ui';
import { IconDown, IconPlus, IconTrash, IconUp } from '../icons';

export default function ProfilesPage() {
  const { can } = useSession();
  const isAdmin = can('admin');
  const profiles = useLoad(api.listProfiles);
  const servers = useLoad(api.listServers);
  const [selected, setSelected] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [dirty, setDirty] = useState(false);
  useLiveRefresh(['config.changed'], () => {
    if (!dirty) void profiles.reload();
  });

  const list = profiles.data ?? [];
  useEffect(() => {
    if (!selected && list.length) setSelected(list[0].name);
    if (selected && profiles.data && !list.some((p) => p.name === selected)) setSelected(list[0]?.name ?? null);
  }, [list, selected, profiles.data]);
  const current = list.find((p) => p.name === selected) ?? null;

  return (
    <>
      <PageHead
        title="Profiles"
        sub="A profile lists the servers an AI tool can reach and the rules that decide each call: allow, ask a human, or deny. The first matching rule wins."
        actions={isAdmin && (
          <button type="button" className="primary" onClick={() => setCreating(true)}>
            <IconPlus size={16} /> New profile
          </button>
        )}
      />
      <ErrorNotice error={profiles.error} />
      {profiles.loading && !profiles.data ? (
        <Loading />
      ) : list.length === 0 ? (
        <div className="card">
          <Empty title="No profiles yet" action={isAdmin && (
            <button type="button" className="primary" onClick={() => setCreating(true)}><IconPlus size={16} /> Create your first profile</button>
          )}>
            Profiles decide what your AI tools may do.
          </Empty>
        </div>
      ) : (
        <div className="stack">
          <div className="row" role="group" aria-label="Profiles">
            {list.map((p) => (
              <button key={p.name} type="button" className={p.name === selected ? 'primary sm' : 'sm'} aria-pressed={p.name === selected}
                onClick={() => setSelected(p.name)}>
                {p.name} <span className="muted small" style={{ color: 'inherit', opacity: 0.75 }}>· {p.rules.length} rules</span>
              </button>
            ))}
          </div>
          {current && (
            <ProfileEditor key={current.name} profile={current} servers={servers.data ?? []} readOnly={!isAdmin}
              onDirty={setDirty}
              onSaved={async () => { setDirty(false); await profiles.reload(); }}
              onDeleted={async () => { setDirty(false); setSelected(null); await profiles.reload(); }} />
          )}
          <Simulator profiles={list} />
        </div>
      )}
      {creating && (
        <NewProfileDialog
          existing={list.map((p) => p.name)}
          onClose={() => setCreating(false)}
          onCreated={async (name) => { setCreating(false); await profiles.reload(); setSelected(name); }}
        />
      )}
    </>
  );
}

function NewProfileDialog({ existing, onClose, onCreated }: { existing: string[]; onClose: () => void; onCreated: (name: string) => void }) {
  const [name, setName] = useState('');
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const n = name.trim();
    if (existing.includes(n)) {
      setErr(new Error(`A profile named "${n}" already exists.`));
      return;
    }
    setBusy(true);
    try {
      await api.putProfile({ name: n, servers: [], rules: [] });
      onCreated(n);
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  };
  return (
    <Dialog title="New profile" onClose={onClose}>
      <form onSubmit={submit}>
        <ErrorNotice error={err} />
        <div className="field">
          <label htmlFor="np-name">Name</label>
          <input id="np-name" type="text" value={name} onChange={(e) => setName(e.target.value)} required placeholder="read-only" />
        </div>
        <div className="dialog-foot">
          <button type="button" onClick={onClose}>Cancel</button>
          <button type="submit" className="primary" disabled={busy}>Create profile</button>
        </div>
      </form>
    </Dialog>
  );
}

interface EditRule extends Rule {
  key: number;
}

let ruleKey = 1;

/** Finds the 1-based rule number in a server validation message such as `profile "x" rule 2: …`. */
function ruleFromError(err: unknown): number | null {
  if (!(err instanceof Error)) return null;
  const m = /rule (\d+)/.exec(err.message);
  return m ? Number(m[1]) : null;
}

function ProfileEditor({
  profile,
  servers,
  readOnly,
  onSaved,
  onDeleted,
  onDirty,
}: {
  profile: Profile;
  servers: Server[];
  readOnly: boolean;
  onSaved: () => Promise<void>;
  onDeleted: () => Promise<void>;
  onDirty: (d: boolean) => void;
}) {
  const [rules, setRules] = useState<EditRule[]>(() => profile.rules.map((r) => ({ ...r, when: r.when || 'any', key: ruleKey++ })));
  const [srv, setSrv] = useState<string[]>(profile.servers);
  const [rate, setRate] = useState<string>(profile.rate_limit?.per_minute ? String(profile.rate_limit.per_minute) : '');
  const [err, setErr] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [dirty, setDirtyState] = useState(false);
  const setDirty = () => {
    setDirtyState(true);
    setSaved(false);
    onDirty(true);
  };
  const errRow = ruleFromError(err);

  const update = (i: number, patch: Partial<Rule>) => {
    setRules((rs) => rs.map((r, j) => (j === i ? { ...r, ...patch } : r)));
    setDirty();
  };
  const move = (i: number, d: -1 | 1) => {
    setRules((rs) => {
      const j = i + d;
      if (j < 0 || j >= rs.length) return rs;
      const out = rs.slice();
      [out[i], out[j]] = [out[j], out[i]];
      return out;
    });
    setDirty();
  };
  const remove = (i: number) => {
    setRules((rs) => rs.filter((_, j) => j !== i));
    setDirty();
  };
  const add = () => {
    setRules((rs) => [...rs, { tool: '', when: 'any', action: 'ask', key: ruleKey++ }]);
    setDirty();
    window.setTimeout(() => document.getElementById(`rule-tool-${rules.length}`)?.focus(), 0);
  };

  const save = async () => {
    setErr(null);
    setSaved(false);
    setBusy(true);
    try {
      const per = Number(rate);
      await api.putProfile({
        name: profile.name,
        servers: srv,
        rules: rules.map(({ tool, when, action }) => ({ tool: tool.trim(), when: when === 'any' ? undefined : when, action })),
        rate_limit: rate !== '' ? { per_minute: Number.isFinite(per) ? per : -1 } : undefined,
      });
      setSaved(true);
      setDirtyState(false);
      onDirty(false);
      await onSaved();
    } catch (e) {
      setErr(e);
    } finally {
      setBusy(false);
    }
  };

  const allServers = useMemo(() => {
    const ids = new Set(servers.map((s) => s.id));
    return [...servers.map((s) => ({ id: s.id, name: s.name, prefix: s.prefix })), ...srv.filter((id) => !ids.has(id)).map((id) => ({ id, name: id, prefix: '' }))];
  }, [servers, srv]);

  // UI-016: rules that name a server the profile can't reach do nothing.
  const missing = useMemo(() => {
    const byPrefix = new Map(servers.map((s) => [s.prefix, s]));
    const out = new Map<string, Server>();
    for (const r of rules) {
      const i = r.tool.indexOf('__');
      if (i <= 0) continue;
      const s = byPrefix.get(r.tool.slice(0, i));
      if (s && !srv.includes(s.id)) out.set(s.id, s);
    }
    return [...out.values()];
  }, [rules, servers, srv]);
  const noServers = srv.length === 0 && servers.length > 0;
  return (
    <section className="card" aria-labelledby="pe-h">
      <div className="row" style={{ marginBottom: 12 }}>
        <h2 id="pe-h" style={{ margin: 0 }}>Profile: {profile.name}</h2>
        <span className="spacer" />
        {!readOnly && (
          <>
            <button type="button" className="danger sm" onClick={() => setDeleting(true)}>Delete profile</button>
            <button type="button" className="primary" onClick={save} disabled={busy || !dirty}>Save</button>
          </>
        )}
      </div>
      {saved && <Notice kind="success">Profile saved.</Notice>}
      <ErrorNotice error={err} />

      {(noServers || missing.length > 0) && (
        <div data-testid="profile-server-warning">
          <Notice kind="warn">
            {noServers && <><strong>No servers are checked, so AI tools using this profile see no tools.</strong> </>}
            {missing.length > 0 && (
              <>
                Rules mention {missing.map((s, i) => <span key={s.id}>{i > 0 && ', '}<strong>{s.name}</strong></span>)}, but{' '}
                {missing.length === 1 ? 'that server isn\u2019t' : 'those servers aren\u2019t'} checked, so {missing.length === 1 ? 'its' : 'their'} tools are hidden.{' '}
                {!readOnly && (
                  <button type="button" className="sm" onClick={() => { setSrv((cur) => [...cur, ...missing.map((s) => s.id)]); setDirty(); }}>
                    Check these servers
                  </button>
                )}
              </>
            )}
          </Notice>
        </div>
      )}
      <h3>Servers</h3>
      {allServers.length === 0 ? (
        <p className="muted small">No servers yet.</p>
      ) : (
        <fieldset className="row" style={{ border: 0, padding: 0, margin: '0 0 16px', gap: 16 }}>
          <legend className="sr-only">Servers in this profile</legend>
          {allServers.map((s) => (
            <label key={s.id} className="checkbox">
              <input type="checkbox" disabled={readOnly} checked={srv.includes(s.id)}
                onChange={(e) => { setSrv((cur) => (e.target.checked ? [...cur, s.id] : cur.filter((x) => x !== s.id))); setDirty(); }} />
              {s.name}
            </label>
          ))}
        </fieldset>
      )}
      <p className="muted small" style={{ marginTop: -8 }}>AI tools using this profile can only reach the checked servers.</p>

      <h3>Rules</h3>
      <p className="muted small">Patterns match namespaced tool names; <code>*</code> is a wildcard, e.g. <code>github__merge_*</code>. Calls that match no rule are denied.</p>
      <div className="table-wrap">
        <table aria-label="Rules">
          <thead>
            <tr>
              <th style={{ width: 36 }}>#</th>
              <th>Tool pattern</th>
              <th>When</th>
              <th>Action</th>
              {!readOnly && <th><span className="sr-only">Reorder and delete</span></th>}
            </tr>
          </thead>
          <tbody>
            {rules.length === 0 && (
              <tr><td colSpan={5} className="muted">No rules: every call is denied. {readOnly ? '' : 'Add a rule to allow tools.'}</td></tr>
            )}
            {rules.map((r, i) => (
              <tr key={r.key} className={errRow === i + 1 ? 'row-error' : ''} data-testid={`rule-row-${i}`}>
                <td className="muted">{i + 1}</td>
                <td>
                  {readOnly ? <code>{r.tool}</code> : (
                    <input id={`rule-tool-${i}`} className="rule-pattern" title={r.tool} type="text" value={r.tool} aria-label={`Rule ${i + 1} tool pattern`}
                      aria-invalid={errRow === i + 1} onChange={(e) => update(i, { tool: e.target.value })} placeholder="server__tool_*" />
                  )}
                  {errRow === i + 1 && <div className="field-error">{err instanceof Error ? err.message : ''}</div>}
                </td>
                <td>
                  {readOnly ? (r.when || 'any').replace('_', ' ') : (
                    <select className="compact" value={r.when || 'any'} aria-label={`Rule ${i + 1} when`} onChange={(e) => update(i, { when: e.target.value as When })}>
                      <option value="any">Any</option>
                      <option value="read_only">Read-only</option>
                      <option value="write">Write</option>
                    </select>
                  )}
                </td>
                <td>
                  {readOnly ? <span className={`badge ${r.action === 'allow' ? 'ok' : r.action === 'deny' ? 'danger' : 'warn'}`}>{r.action}</span> : (
                    <select className="compact" value={r.action} aria-label={`Rule ${i + 1} action`} onChange={(e) => update(i, { action: e.target.value as Action })}>
                      <option value="allow">Allow</option>
                      <option value="ask">Ask</option>
                      <option value="deny">Deny</option>
                    </select>
                  )}
                </td>
                {!readOnly && (
                  <td className="actions">
                    <div className="row end" style={{ gap: 4, flexWrap: 'nowrap' }}>
                      <button type="button" className="icon sm ghost" onClick={() => move(i, -1)} disabled={i === 0} aria-label={`Move rule ${i + 1} up`}><IconUp size={15} /></button>
                      <button type="button" className="icon sm ghost" onClick={() => move(i, 1)} disabled={i === rules.length - 1} aria-label={`Move rule ${i + 1} down`}><IconDown size={15} /></button>
                      <button type="button" className="icon sm ghost" onClick={() => remove(i)} aria-label={`Delete rule ${i + 1}`}><IconTrash size={15} /></button>
                    </div>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!readOnly && (
        <div className="row" style={{ marginTop: 10 }}>
          <button type="button" className="sm" onClick={add}><IconPlus size={14} /> Add rule</button>
        </div>
      )}

      <div className="field" style={{ marginTop: 16, maxWidth: 260 }}>
        <label htmlFor="pe-rate">Rate limit (calls per minute per AI tool)</label>
        <input id="pe-rate" type="number" min={0} value={rate} disabled={readOnly} placeholder="No limit"
          onChange={(e) => { setRate(e.target.value); setDirty(); }} />
      </div>
      {deleting && (
        <Confirm
          title={`Delete profile ${profile.name}?`}
          body={<p>AI tools using this profile will be denied until they are moved to another profile.</p>}
          confirmLabel="Delete profile"
          onClose={() => setDeleting(false)}
          onConfirm={async () => {
            await api.deleteProfile(profile.name);
            await onDeleted();
          }}
        />
      )}
    </section>
  );
}

function Simulator({ profiles }: { profiles: Profile[] }) {
  const [profile, setProfile] = useState(profiles[0]?.name ?? '');
  const [tool, setTool] = useState('');
  const [ro, setRo] = useState(false);
  const [res, setRes] = useState<{ decision: Decision; server_id: string } | null>(null);
  const [err, setErr] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const run = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    setBusy(true);
    try {
      setRes(await api.simulate(profile, tool.trim(), ro));
    } catch (e2) {
      setErr(e2);
      setRes(null);
    } finally {
      setBusy(false);
    }
  };
  const p = profiles.find((x) => x.name === profile);
  const rule = res && p && res.decision.rule_index >= 0 ? p.rules[res.decision.rule_index] : undefined;
  return (
    <section className="card" aria-labelledby="sim-h">
      <h2 id="sim-h">Rule simulator</h2>
      <p className="muted small">Check what would happen if an AI tool called a tool. Uses the saved rules.</p>
      <form onSubmit={run} className="filters" aria-label="Rule simulator">
        <div className="field">
          <label htmlFor="sim-profile">Profile</label>
          <select id="sim-profile" value={profile} onChange={(e) => setProfile(e.target.value)}>
            {profiles.map((x) => <option key={x.name} value={x.name}>{x.name}</option>)}
          </select>
        </div>
        <div className="field" style={{ flex: 1, minWidth: 200 }}>
          <label htmlFor="sim-tool">Tool name</label>
          <input id="sim-tool" type="text" value={tool} onChange={(e) => setTool(e.target.value)} placeholder="github__merge_pr" required />
        </div>
        <div className="field" style={{ minWidth: 0 }}>
          <label className="checkbox" style={{ paddingBottom: 8 }}>
            <input type="checkbox" checked={ro} onChange={(e) => setRo(e.target.checked)} /> Read-only tool
          </label>
        </div>
        <button type="submit" className="primary" disabled={busy}>Simulate</button>
      </form>
      <ErrorNotice error={err} />
      {res && (
        <div className="notice info" role="status" data-testid="sim-result">
          <div className="grow">
            <div>
              Decision: <strong data-testid="sim-decision">{res.decision.action}</strong>
            </div>
            <div className="small">
              {res.decision.rule_index >= 0 ? (
                <>Matched rule {res.decision.rule_index + 1}{rule && <>: <code>{rule.tool}</code>{rule.when && rule.when !== 'any' ? ` (${rule.when.replace('_', ' ')})` : ''} → {rule.action}</>}</>
              ) : (
                <>No rule matched.</>
              )}
              {res.decision.reason && <> · {res.decision.reason}</>}
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
