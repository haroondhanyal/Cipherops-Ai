import { useCallback, useEffect, useState } from 'react';
import { LockKeyhole } from 'lucide-react';
import { Badge } from '../components/Badge';
import { api } from '../shared';

type SsoStatus = { enabled: boolean; provider: string };

export function SecuritySettings({ token }: { token: string }) {
  const [enabled, setEnabled] = useState(false);
  const [sso, setSso] = useState<SsoStatus | null>(null);
  const [secret, setSecret] = useState('');
  const [uri, setUri] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const [mfaStatus, ssoStatus] = await Promise.all([
        api<{ enabled: boolean }>('/auth/mfa/status', token),
        api<SsoStatus>('/auth/sso/status', token),
      ]);
      setEnabled(mfaStatus.enabled);
      setSso(ssoStatus);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to read security status');
    }
  }, [token]);

  useEffect(() => { void refresh(); }, [refresh]);

  async function setup() {
    setBusy(true); setError('');
    try {
      const result = await api<{ secret: string; provisioning_uri: string }>('/auth/mfa/setup', token, { method: 'POST' });
      setSecret(result.secret); setUri(result.provisioning_uri);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Could not start MFA setup');
    } finally { setBusy(false); }
  }

  async function confirm() {
    setBusy(true); setError('');
    try {
      await api('/auth/mfa/verify', token, { method: 'POST', body: JSON.stringify({ code }) });
      setSecret(''); setUri(''); setCode(''); await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'MFA code was rejected');
    } finally { setBusy(false); }
  }

  async function disable() {
    setBusy(true); setError('');
    try {
      await api('/auth/mfa/disable', token, { method: 'POST', body: JSON.stringify({ code }) });
      setCode(''); await refresh();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'MFA code was rejected');
    } finally { setBusy(false); }
  }

  return <>
    <div className="page-head"><div><div className="eyebrow">ACCOUNT / SESSION SECURITY</div><h1>Security settings</h1><p className="subtitle">Protect sign-in with a time-based authenticator code.</p></div><Badge tone={enabled ? 'blue' : 'amber'}>{enabled ? 'MFA enabled' : 'MFA not enabled'}</Badge></div>
    <section className="panel mfa-card">
      <div className="mfa-card-heading"><div className="metric-icon blue"><LockKeyhole size={18}/></div><div><h2>Authenticator app (TOTP)</h2><p>Compatible with common authenticator apps. Setup secrets are only shown during enrollment.</p></div></div>
      {!enabled && !secret && <button className="button primary" onClick={() => void setup()} disabled={busy}>{busy ? 'Preparing…' : 'Set up MFA'}</button>}
      {secret && !enabled && <div className="mfa-setup"><p>Add this key to your authenticator app, then enter its current 6-digit code to confirm.</p><code>{secret}</code><a href={uri}>Open authenticator setup link</a><div className="mfa-confirm"><input inputMode="numeric" maxLength={6} placeholder="6-digit code" value={code} onChange={event => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}/><button className="button primary" onClick={() => void confirm()} disabled={busy || code.length !== 6}>Confirm and enable</button></div></div>}
      {enabled && <div className="mfa-confirm"><input inputMode="numeric" maxLength={6} placeholder="Current authenticator code" value={code} onChange={event => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}/><button className="button secondary" onClick={() => void disable()} disabled={busy || code.length !== 6}>Disable MFA</button></div>}
    </section>
    <section className="panel mfa-card"><div className="mfa-card-heading"><div className="metric-icon blue"><LockKeyhole size={18}/></div><div><h2>Company single sign-on</h2><p>Organization-managed OpenID Connect sign-in.</p></div></div>
      {sso?.enabled ? <Badge tone="blue">Enabled · {sso.provider}</Badge> : <><Badge tone="amber">Not configured</Badge><p className="subtitle">Set OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET and OIDC_REDIRECT_URI in backend/.env, register the matching callback with your identity provider, then restart the API.</p></>}
    </section>
    {error && <div className="admin-error">{error}</div>}
  </>;
}
