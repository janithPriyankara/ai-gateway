import { useRef, useState } from 'react';
import * as api from '../api';
import { useSession } from '../session';
import { Confirm, ErrorNotice, Loading, Notice, PageHead, formatTime, useLoad } from '../components/ui';

export default function SecurityPage() {
  const { can } = useSession();
  const sec = useLoad(api.getSecurity);
  const [err, setErr] = useState<unknown>(null);
  const [msg, setMsg] = useState<string | null>(null);
  const [rotating, setRotating] = useState(false);
  const [importText, setImportText] = useState<{ name: string; text: string } | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const doExport = async () => {
    setErr(null);
    setMsg(null);
    try {
      const yaml = await api.exportConfig();
      const blob = new Blob([yaml], { type: 'application/yaml' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'mcp-gateway-config.yaml';
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      setMsg('Configuration exported. It contains servers, profiles and pins, but no secrets.');
    } catch (e) {
      setErr(e);
    }
  };

  const onFile = async (f: File | undefined) => {
    setErr(null);
    setMsg(null);
    if (!f) return;
    if (f.size > 1 << 20) {
      setErr(new Error('That file is larger than 1 MB. Choose a config exported from mcp-gateway.'));
      return;
    }
    setImportText({ name: f.name, text: await f.text() });
  };

  const kp = sec.data?.key_provider;
  const sk = sec.data?.signing_key;
  return (
    <>
      <PageHead title="Security" sub="How the gateway protects credentials and tokens." />
      {msg && <Notice kind="success">{msg}</Notice>}
      <ErrorNotice error={sec.error ?? err} onDismiss={err ? () => setErr(null) : undefined} />
      {sec.loading && !sec.data ? <Loading /> : sec.data && kp && sk ? (
        <div className="stack">
          <section className="card" aria-labelledby="kp-h">
            <h2 id="kp-h">Master key</h2>
            <div className="row" style={{ gap: 12 }}>
              <div>
                <div className="muted small">Key provider</div>
                <strong data-testid="key-provider">{kp.name}</strong>
              </div>
              <div>
                <div className="muted small">Strength</div>
                <span className={`badge ${kp.strength === 'strong' ? 'ok' : 'warn'}`} data-testid="key-strength">{kp.strength}</span>
              </div>
              <div>
                <div className="muted small">Status</div>
                {kp.healthy ? <span className="badge ok">Healthy</span> : <span className="badge danger">Unavailable</span>}
              </div>
            </div>
            {kp.strength !== 'strong' && (
              <p className="muted small" style={{ marginTop: 12, marginBottom: 0 }}>
                This provider is not hardware- or KMS-backed. For exposed deployments prefer the macOS keychain, a TPM or a cloud KMS.
              </p>
            )}
          </section>
          <section className="card" aria-labelledby="sk-h">
            <h2 id="sk-h">Token signing key</h2>
            <p className="muted small">Signs the OAuth access tokens issued to AI tools. Rotating keeps the old key valid for tokens already issued.</p>
            <div className="row" style={{ gap: 12 }}>
              <div>
                <div className="muted small">Age</div>
                <strong data-testid="signing-age">{sk.age_days} day{sk.age_days === 1 ? '' : 's'}</strong>
              </div>
              <div>
                <div className="muted small">Created</div>
                <span>{formatTime(sk.created_at)}</span>
              </div>
              <div>
                <div className="muted small">Key ID</div>
                <code data-testid="signing-kid">{sk.kid}</code>
              </div>
              <span className="spacer" />
              {can('owner') && <button type="button" onClick={() => setRotating(true)}>Rotate</button>}
            </div>
          </section>
          <section className="card" aria-labelledby="cfg-h">
            <h2 id="cfg-h">Configuration</h2>
            <p className="muted small">Export servers, profiles and tool pins as YAML (no secrets), or import a file to replace them.</p>
            <div className="row">
              {can('admin') && <button type="button" onClick={doExport}>Export config</button>}
              {can('owner') && (
                <>
                  <input ref={fileRef} id="import-file" type="file" accept=".yaml,.yml,application/yaml,text/yaml" className="sr-only"
                    onChange={(e) => { void onFile(e.target.files?.[0]); e.target.value = ''; }} />
                  <button type="button" onClick={() => fileRef.current?.click()}>Import config…</button>
                </>
              )}
              {!can('admin') && <span className="muted small">Only admins can export and only owners can import.</span>}
            </div>
          </section>
        </div>
      ) : null}
      {rotating && (
        <Confirm
          title="Rotate the signing key?"
          body={<p>New tokens will be signed with a new key. Existing tokens stay valid until they expire.</p>}
          confirmLabel="Rotate key"
          onClose={() => setRotating(false)}
          onConfirm={async () => {
            const r = await api.rotateSigningKey();
            sec.setData((cur) => (cur ? { ...cur, signing_key: r.signing_key } : cur));
            setMsg('Signing key rotated.');
          }}
        />
      )}
      {importText && (
        <Confirm
          title={`Import ${importText.name}?`}
          body={<p>This replaces the current servers, profiles and pins with the contents of the file. Credentials are not affected.</p>}
          confirmLabel="Import"
          onClose={() => setImportText(null)}
          onConfirm={async () => {
            await api.importConfig(importText.text);
            setMsg(`Imported ${importText.name}.`);
          }}
        />
      )}
    </>
  );
}
