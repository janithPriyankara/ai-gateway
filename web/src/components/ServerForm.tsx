import { useState, type FormEvent } from 'react';
import * as api from '../api';
import type { CatalogEntry, Rule, Server } from '../api';
import { Dialog, ErrorNotice, Loading, Tabs, useLoad } from './ui';

const blank: Server = { id: '', name: '', prefix: '', transport: 'http', url: '', command: '', args: [], auth_kind: 'none', enabled: true };

function slug(s: string): string {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').replace(/__+/g, '_').slice(0, 32);
}

/** Server create/edit form. In create mode it offers the catalog and a manual form. */
export function ServerDialog({
  initial,
  onClose,
  onSaved,
}: {
  initial?: Server;
  onClose: () => void;
  onSaved: (s: Server) => void;
}) {
  const editing = !!initial;
  const [tab, setTab] = useState<'catalog' | 'manual'>(editing ? 'manual' : 'catalog');
  const [form, setForm] = useState<Server>(initial ? { ...blank, ...initial } : blank);
  const [argsText, setArgsText] = useState((initial?.args ?? []).join('\n'));
  const [rules, setRules] = useState<Rule[] | undefined>(undefined);
  const [fromCatalog, setFromCatalog] = useState<CatalogEntry | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const catalog = useLoad(() => (editing ? Promise.resolve([] as CatalogEntry[]) : api.getCatalog()));

  const set = <K extends keyof Server>(k: K, v: Server[K]) => setForm((f) => ({ ...f, [k]: v }));

  const pick = (e: CatalogEntry) => {
    setFromCatalog(e);
    setForm({ ...blank, ...e.server, id: e.server.id || '' });
    setArgsText((e.server.args ?? []).join('\n'));
    setRules(e.rules);
    setTab('manual');
  };

  const submit = async (ev: FormEvent) => {
    ev.preventDefault();
    setErr(null);
    setBusy(true);
    // Send only the fields the API knows: it rejects unknown JSON fields.
    const body: Server = {
      name: form.name,
      prefix: form.prefix,
      transport: form.transport,
      auth_kind: form.auth_kind,
      enabled: form.enabled,
      id: form.id || form.prefix.replace(/_/g, '-'),
      args: form.transport === 'stdio' ? argsText.split('\n').map((s) => s.trim()).filter(Boolean) : undefined,
      url: form.transport === 'http' ? form.url : undefined,
      command: form.transport === 'stdio' ? form.command : undefined,
      timeout_seconds: form.timeout_seconds || undefined,
    };
    try {
      const saved = editing ? await api.updateServer(initial.id, body) : await api.createServer({ ...body, rules });
      onSaved(saved);
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };

  return (
    <Dialog title={editing ? `Edit ${initial.name}` : 'Add server'} onClose={onClose} wide>
      {!editing && (
        <Tabs label="How to add" value={tab} onChange={setTab}
          tabs={[{ id: 'catalog', label: 'From catalog' }, { id: 'manual', label: fromCatalog ? 'Review' : 'Manual' }]} />
      )}
      {tab === 'catalog' && !editing ? (
        catalog.loading ? (
          <Loading />
        ) : (
          <>
            <ErrorNotice error={catalog.error} />
            <ul className="list" aria-label="Catalog">
              {(catalog.data ?? []).map((e) => (
                <li key={e.server.prefix}>
                  <div style={{ flex: 1, minWidth: 200 }}>
                    <strong>{e.server.name}</strong> <span className="badge">{e.server.transport}</span>
                    <div className="muted small">{e.description}</div>
                  </div>
                  <button type="button" className="sm" onClick={() => pick(e)} aria-label={`Use ${e.server.name}`}>
                    Use
                  </button>
                </li>
              ))}
            </ul>
            <p className="muted small" style={{ marginTop: 12 }}>
              Not listed? <button type="button" className="sm ghost" onClick={() => setTab('manual')}>Add it manually</button>
            </p>
          </>
        )
      ) : (
        <form onSubmit={submit} aria-label="Server details">
          <ErrorNotice error={err} />
          {fromCatalog && (
            <p className="muted small">
              From the catalog. {rules && rules.length > 0 && `${rules.length} suggested rules will be added to the default profile.`}
            </p>
          )}
          <div className="two-col">
            <div className="field">
              <label htmlFor="sv-name">Name</label>
              <input id="sv-name" type="text" value={form.name} required
                onChange={(e) => {
                  const name = e.target.value;
                  setForm((f) => ({ ...f, name, prefix: editing || (f.prefix && f.prefix !== slug(f.name)) ? f.prefix : slug(name) }));
                }} />
            </div>
            <div className="field">
              <label htmlFor="sv-prefix">Tool prefix</label>
              <input id="sv-prefix" type="text" value={form.prefix} required onChange={(e) => set('prefix', e.target.value)}
                aria-describedby="sv-prefix-hint" />
              <div className="hint" id="sv-prefix-hint">Tools appear as <code>{form.prefix || 'prefix'}__tool</code>.</div>
            </div>
          </div>
          <div className="two-col">
            <div className="field">
              <label htmlFor="sv-transport">Transport</label>
              <select id="sv-transport" value={form.transport} onChange={(e) => set('transport', e.target.value as Server['transport'])}>
                <option value="http">HTTP (remote)</option>
                <option value="stdio">Stdio (local command)</option>
              </select>
            </div>
            <div className="field">
              <label htmlFor="sv-auth">Authentication</label>
              <select id="sv-auth" value={form.auth_kind} onChange={(e) => set('auth_kind', e.target.value)}>
                <option value="none">None</option>
                <option value="bearer">Bearer token</option>
                <option value="header">Custom header</option>
                <option value="env">Environment variables</option>
                <option value="oauth">OAuth</option>
              </select>
            </div>
          </div>
          {form.transport === 'http' ? (
            <div className="field">
              <label htmlFor="sv-url">URL</label>
              <input id="sv-url" type="url" value={form.url ?? ''} required placeholder="https://example.com/mcp"
                onChange={(e) => set('url', e.target.value)} />
            </div>
          ) : (
            <div className="two-col">
              <div className="field">
                <label htmlFor="sv-cmd">Command</label>
                <input id="sv-cmd" type="text" value={form.command ?? ''} required placeholder="npx"
                  onChange={(e) => set('command', e.target.value)} />
              </div>
              <div className="field">
                <label htmlFor="sv-args">Arguments (one per line)</label>
                <textarea id="sv-args" value={argsText} onChange={(e) => setArgsText(e.target.value)} rows={3} />
              </div>
            </div>
          )}
          <div className="two-col">
            <div className="field">
              <label htmlFor="sv-timeout">Timeout (seconds)</label>
              <input id="sv-timeout" type="number" min={0} max={3600} value={form.timeout_seconds ?? ''}
                onChange={(e) => set('timeout_seconds', e.target.value ? Number(e.target.value) : undefined)} />
            </div>
            <div className="field" style={{ alignSelf: 'end' }}>
              <label className="checkbox">
                <input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} /> Enabled
              </label>
            </div>
          </div>
          <div className="dialog-foot">
            <button type="button" onClick={onClose}>Cancel</button>
            <button type="submit" className="primary" disabled={busy}>
              {editing ? 'Save changes' : 'Add server'}
            </button>
          </div>
        </form>
      )}
    </Dialog>
  );
}
