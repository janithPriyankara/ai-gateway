import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { browserSupportsWebAuthn, startAuthentication } from '@simplewebauthn/browser';
import type { PublicKeyCredentialRequestOptionsJSON } from '@simplewebauthn/browser';
import * as api from '../api';
import { ErrorNotice } from '../components/ui';
import { IconKey } from '../icons';

/** Only same-origin paths are allowed as a post-login destination (no open redirects). */
export function safeNext(next: string | null): string {
  if (!next) return '/admin/';
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/admin/';
  return next;
}

export default function LoginPage() {
  const [params] = useSearchParams();
  const next = safeNext(params.get('next'));
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<unknown>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    // Already signed in? Go straight to the destination. First run? Go to setup.
    (async () => {
      try {
        await api.me();
        window.location.assign(next);
        return;
      } catch {
        /* not signed in */
      }
      try {
        const st = await api.authStatus();
        if (st.setup_required) {
          window.location.assign('/admin/setup');
          return;
        }
      } catch {
        /* show the login form anyway */
      }
      setChecking(false);
    })();
  }, [next]);

  const signIn = async () => {
    setErr(null);
    if (!browserSupportsWebAuthn()) {
      setErr(new Error('This browser does not support passkeys.'));
      return;
    }
    setBusy(true);
    try {
      const { ceremony, options } = await api.loginBegin();
      const credential = await startAuthentication({
        optionsJSON: options.publicKey as unknown as PublicKeyCredentialRequestOptionsJSON,
      });
      await api.loginFinish(ceremony, credential);
      // Full navigation: the destination may be a server-rendered page such as /oauth/authorize.
      window.location.assign(next);
    } catch (e) {
      setErr(e);
      setBusy(false);
    }
  };

  return (
    <div className="auth-wrap">
      <main className="card auth-card">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">g</span> mcp-gateway
        </div>
        <h1>Sign in</h1>
        <p className="muted" style={{ marginTop: 6 }}>
          Use the passkey you registered for this gateway.
          {next.startsWith('/oauth/') && ' You will then be asked to connect your AI tool.'}
        </p>
        <ErrorNotice error={err} />
        <button type="button" className="primary" onClick={signIn} disabled={busy || checking} style={{ width: '100%', justifyContent: 'center' }}>
          <IconKey size={16} /> {busy ? 'Waiting for passkey…' : 'Sign in with a passkey'}
        </button>
        <p className="muted small" style={{ marginTop: 14, marginBottom: 0 }}>
          No account? Ask an admin for an invite link.
        </p>
      </main>
    </div>
  );
}
