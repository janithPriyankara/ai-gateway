import { useState, type FormEvent } from 'react';
import { useSearchParams } from 'react-router-dom';
import { browserSupportsWebAuthn, startRegistration } from '@simplewebauthn/browser';
import type { PublicKeyCredentialCreationOptionsJSON } from '@simplewebauthn/browser';
import * as api from '../api';
import { ErrorNotice } from '../components/ui';
import { IconKey } from '../icons';

function RegisterForm({ mode }: { mode: 'setup' | 'invite' }) {
  const [params] = useSearchParams();
  const token = params.get('token') ?? '';
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setErr(null);
    if (!name.trim()) {
      setErr(new Error('Enter your name.'));
      return;
    }
    if (!browserSupportsWebAuthn()) {
      setErr(new Error('This browser does not support passkeys.'));
      return;
    }
    setBusy(true);
    try {
      const begin = mode === 'setup' ? api.setupBegin : api.inviteBegin;
      const { ceremony, options } = await begin(token, name.trim());
      const credential = await startRegistration({
        optionsJSON: options.publicKey as unknown as PublicKeyCredentialCreationOptionsJSON,
      });
      await api.registerFinish(ceremony, credential);
      window.location.assign('/admin/');
    } catch (e2) {
      setErr(e2);
      setBusy(false);
    }
  };

  const title = mode === 'setup' ? 'Set up mcp-gateway' : 'Join mcp-gateway';
  return (
    <div className="auth-wrap">
      <main className="card auth-card">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">g</span> mcp-gateway
        </div>
        <h1>{title}</h1>
        {!token ? (
          <p className="muted" style={{ marginTop: 6 }}>
            {mode === 'setup'
              ? 'Open the setup link printed in the gateway log when it first started. It contains a one-time token.'
              : 'This invite link is missing its token. Ask the person who invited you for a new link.'}
          </p>
        ) : (
          <form onSubmit={submit}>
            <p className="muted" style={{ marginTop: 6 }}>
              {mode === 'setup'
                ? 'Create the owner account. You will sign in with a passkey: no password needed.'
                : 'You were invited to this gateway. Choose a name and register a passkey.'}
            </p>
            <ErrorNotice error={err} />
            <div className="field">
              <label htmlFor="reg-name">Your name</label>
              <input id="reg-name" type="text" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" autoFocus
                maxLength={80} />
            </div>
            <button type="submit" className="primary" disabled={busy} style={{ width: '100%', justifyContent: 'center' }}>
              <IconKey size={16} /> {busy ? 'Waiting for passkey…' : 'Create passkey'}
            </button>
          </form>
        )}
      </main>
    </div>
  );
}

export const SetupPage = () => <RegisterForm mode="setup" />;
export const InvitePage = () => <RegisterForm mode="invite" />;
