import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { ImagePlus, LockKeyhole, ShieldCheck, X } from 'lucide-react';
import { Badge } from '../components/Badge';
import { api, imageToAvatar, type SessionUser } from '../shared';
import { CountryPicker } from '../components/CountryPicker';
import { UserAvatar } from '../components/UserAvatar';
import { COUNTRIES, type Country } from '../data/countries';

type SsoStatus = { enabled: boolean; provider: string };
type Profile = Pick<SessionUser, 'first_name' | 'last_name' | 'phone_country' | 'phone_dial_code' | 'mobile_number' | 'country_code' | 'country' | 'city' | 'avatar_data'>;

export function SecuritySettings({ token, onProfileUpdate }: { token: string; onProfileUpdate?: (user: SessionUser) => void }) {
  const [enabled, setEnabled] = useState(false);
  const [sso, setSso] = useState<SsoStatus | null>(null);
  const [secret, setSecret] = useState('');
  const [uri, setUri] = useState('');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [profile, setProfile] = useState<Profile | null>(null);
  const [profileMessage, setProfileMessage] = useState('');
  const [role, setRole] = useState('SOC Analyst');

  const refresh = useCallback(async () => {
    try {
      const [mfaStatus, ssoStatus, user] = await Promise.all([
        api<{ enabled: boolean }>('/auth/mfa/status', token),
        api<SsoStatus>('/auth/sso/status', token),
        api<SessionUser>('/auth/me', token),
      ]);
      setEnabled(mfaStatus.enabled);
      setSso(ssoStatus);
      setRole(user.roles[0] || 'SOC Analyst');
      setProfile({ first_name: user.first_name, last_name: user.last_name, phone_country: user.phone_country, phone_dial_code: user.phone_dial_code, mobile_number: user.mobile_number, country_code: user.country_code, country: user.country, city: user.city, avatar_data: user.avatar_data });
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : 'Unable to read security status');
    }
  }, [token]);

  useEffect(() => { void refresh(); }, [refresh]);

  function setProfileField<K extends keyof Profile>(key: K, value: Profile[K]) {
    setProfile(current => current ? { ...current, [key]: value } : current);
    setProfileMessage('');
  }

  async function changeAvatar(file?: File) {
    if (!file) return;
    try { setProfileField('avatar_data', await imageToAvatar(file)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not process this image.'); }
  }

  async function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault(); if (!profile) return;
    setBusy(true); setError(''); setProfileMessage('');
    try {
      const user = await api<SessionUser>('/auth/me', token, { method: 'PATCH', body: JSON.stringify(profile) });
      setRole(user.roles[0] || 'SOC Analyst');
      setProfile({ first_name: user.first_name, last_name: user.last_name, phone_country: user.phone_country, phone_dial_code: user.phone_dial_code, mobile_number: user.mobile_number, country_code: user.country_code, country: user.country, city: user.city, avatar_data: user.avatar_data });
      onProfileUpdate?.(user); setProfileMessage('Profile saved.');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not save profile.'); }
    finally { setBusy(false); }
  }

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
    <div className="page-head"><div><div className="eyebrow">ACCOUNT / SESSION SECURITY</div><h1>Account and security</h1><p className="subtitle">Update your profile and protect sign-in.</p></div><Badge tone={enabled ? 'blue' : 'amber'}>{enabled ? 'MFA enabled' : 'MFA not enabled'}</Badge></div>
    <section className="panel mfa-card profile-card"><div className="mfa-card-heading"><div className="metric-icon blue"><UserAvatar name={`${profile?.first_name || ''} ${profile?.last_name || ''}`} image={profile?.avatar_data}/></div><div><h2>Profile information</h2><p>Edit your name, photo, mobile number and location.</p></div></div>
      {profile && <form className="profile-form" onSubmit={event => void saveProfile(event)}>
        <div className="profile-photo-row"><UserAvatar name={`${profile.first_name || ''} ${profile.last_name || ''}`} image={profile.avatar_data} className="profile-avatar-large"/><label className="button secondary avatar-upload"><ImagePlus size={14}/> {profile.avatar_data ? 'Change photo' : 'Add photo'}<input type="file" accept="image/png,image/jpeg,image/webp" onChange={event => { const file = event.target.files?.[0]; event.target.value = ''; void changeAvatar(file); }}/></label>{profile.avatar_data && <button type="button" className="button secondary" onClick={() => setProfileField('avatar_data', null)}><X size={14}/> Remove photo</button>}</div>
        <div className="auth-grid two"><label className="auth-field"><span>First name</span><input autoComplete="given-name" value={profile.first_name || ''} onChange={event => setProfileField('first_name', event.target.value)} maxLength={75} required/></label><label className="auth-field"><span>Last name</span><input autoComplete="family-name" value={profile.last_name || ''} onChange={event => setProfileField('last_name', event.target.value)} maxLength={75} required/></label></div>
        <div className="auth-grid phone-grid"><CountryPicker label="Calling code" value={profile.phone_country || 'PK'} onChange={(country: Country) => { setProfileField('phone_country', country.code); setProfileField('phone_dial_code', country.dialCode); }} showDialCode/><label className="auth-field"><span>Mobile number</span><input type="tel" inputMode="tel" autoComplete="tel-national" value={profile.mobile_number || ''} onChange={event => setProfileField('mobile_number', event.target.value.replace(/\D/g, '').slice(0, 15))} minLength={6} maxLength={15} required/></label></div>
        <div className="auth-grid two"><CountryPicker label="Country" value={COUNTRIES.some(item => item.code === profile.country_code) ? profile.country_code! : 'PK'} onChange={(country: Country) => { setProfileField('country_code', country.code); setProfileField('country', country.name); }}/><label className="auth-field"><span>City</span><input autoComplete="address-level2" value={profile.city || ''} onChange={event => setProfileField('city', event.target.value)} maxLength={120} required/></label></div>
        <div className="profile-role"><ShieldCheck size={15}/><span>Current role</span><b>{role}</b><small>Contact a workspace administrator to change access.</small></div>
        {profileMessage && <div className="auth-message">{profileMessage}</div>}<button className="button primary" disabled={busy}>{busy ? 'Saving…' : 'Save profile'}</button>
      </form>}
    </section>
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
