import { useEffect, useState, type ChangeEvent, type FormEvent } from 'react';
import { ChevronRight, Eye, EyeOff, ImagePlus, ShieldCheck, X } from 'lucide-react';
import { API, imageToAvatar, type SessionUser } from '../shared';
import { CountryPicker } from '../components/CountryPicker';
import type { Country } from '../data/countries';
import { UserAvatar } from '../components/UserAvatar';

type Screen = 'signin' | 'signup' | 'forgot' | 'reset';
type AuthResponse = { access_token: string; user: SessionUser };

async function responseError(response: Response, fallback: string) {
  const data = await response.json().catch(() => ({}));
  const detail = data.detail;
  if (Array.isArray(detail)) return detail.map(item => item.msg).join(', ') || fallback;
  return typeof detail === 'string' ? detail : fallback;
}

function PasswordInput({ label, value, onChange, autoComplete, minLength = 1 }: {
  label: string; value: string; onChange: (value: string) => void; autoComplete: string; minLength?: number;
}) {
  const [visible, setVisible] = useState(false);
  return <label className="auth-field"><span>{label}</span><span className="password-control">
    <input type={visible ? 'text' : 'password'} autoComplete={autoComplete} value={value} onChange={event => onChange(event.target.value)} minLength={minLength} required/>
    <button type="button" className="password-toggle" onClick={() => setVisible(current => !current)} aria-label={visible ? `Hide ${label.toLowerCase()}` : `Show ${label.toLowerCase()}`} title={visible ? 'Hide password' : 'Show password'}>{visible ? <EyeOff size={16}/> : <Eye size={16}/>}</button>
  </span></label>;
}

export function LoginScreen({ onLogin }: { onLogin: (token: string, user: SessionUser) => void }) {
  const resetFromUrl = new URLSearchParams(window.location.search).get('password_reset') || '';
  const [screen, setScreen] = useState<Screen>(resetFromUrl ? 'reset' : 'signin');
  const [resetToken, setResetToken] = useState(resetFromUrl);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [mfaCode, setMfaCode] = useState('');
  const [remember, setRemember] = useState(false);
  const [error, setError] = useState(() => sessionStorage.getItem('cipherops.sso.error') || '');
  const [message, setMessage] = useState('');
  const [busy, setBusy] = useState(false);
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [signupEnabled, setSignupEnabled] = useState(false);
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [phoneCountry, setPhoneCountry] = useState<Country['code']>('PK');
  const [phoneDialCode, setPhoneDialCode] = useState('+92');
  const [mobileNumber, setMobileNumber] = useState('');
  const [countryCode, setCountryCode] = useState<Country['code']>('PK');
  const [country, setCountry] = useState('Pakistan');
  const [city, setCity] = useState('');
  const [avatarData, setAvatarData] = useState<string | null>(null);

  useEffect(() => {
    sessionStorage.removeItem('cipherops.sso.error');
    if (resetFromUrl) {
      const url = new URL(window.location.href);
      url.searchParams.delete('password_reset');
      window.history.replaceState({}, '', url);
    }
    Promise.all([
      fetch(`${API}/auth/sso/status`).then(response => response.json()),
      fetch(`${API}/auth/config`).then(response => response.json()),
    ]).then(([sso, config]) => {
      setSsoEnabled(Boolean(sso.enabled));
      setSignupEnabled(Boolean(config.public_signup_enabled));
    }).catch(() => {});
  }, [resetFromUrl]);

  function choosePhoneCountry(selected: Country) {
    setPhoneCountry(selected.code); setPhoneDialCode(selected.dialCode);
  }

  async function chooseAvatar(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = '';
    if (!file) return;
    setError('');
    try { setAvatarData(await imageToAvatar(file)); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not load the selected image.'); }
  }

  function persistSession(data: AuthResponse) {
    localStorage.removeItem('cipherops.session'); sessionStorage.removeItem('cipherops.session');
    (remember ? localStorage : sessionStorage).setItem('cipherops.session', JSON.stringify({ token: data.access_token, user: data.user }));
    onLogin(data.access_token, data.user);
  }

  async function submitSignIn(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage(''); setBusy(true);
    try {
      const response = await fetch(`${API}/auth/login`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, mfa_code: mfaCode || null }) });
      if (!response.ok) throw new Error(await responseError(response, 'Sign-in failed.'));
      persistSession(await response.json());
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not reach CipherOps API.'); }
    finally { setBusy(false); }
  }

  async function submitSignup(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage('');
    if (password !== confirmPassword) { setError('Passwords do not match.'); return; }
    setBusy(true);
    try {
      const response = await fetch(`${API}/auth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, first_name: firstName, last_name: lastName, phone_country: phoneCountry, phone_dial_code: phoneDialCode, mobile_number: mobileNumber, country_code: countryCode, country, city, password, confirm_password: confirmPassword, avatar_data: avatarData }) });
      if (!response.ok) throw new Error(await responseError(response, 'Account creation failed.'));
      persistSession(await response.json());
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not reach CipherOps API.'); }
    finally { setBusy(false); }
  }

  async function requestReset(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage(''); setBusy(true);
    try {
      const response = await fetch(`${API}/auth/password/forgot`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email }) });
      if (!response.ok) throw new Error(await responseError(response, 'Password reset request failed.'));
      const data = await response.json();
      setMessage(data.message || 'If the account exists, password reset instructions will be sent.');
      if (data.development_reset_url) setMessage(`${data.message} Local development link:`);
      if (data.development_reset_url) setResetToken(data.development_reset_url);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not reach CipherOps API.'); }
    finally { setBusy(false); }
  }

  async function submitReset(event: FormEvent) {
    event.preventDefault(); setError(''); setMessage('');
    if (password !== confirmPassword) { setError('Passwords do not match.'); return; }
    setBusy(true);
    try {
      const response = await fetch(`${API}/auth/password/reset`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: resetToken, password, confirm_password: confirmPassword }) });
      if (!response.ok) throw new Error(await responseError(response, 'Password reset failed.'));
      const data = await response.json(); setMessage(data.message); setPassword(''); setConfirmPassword(''); setResetToken(''); setScreen('signin');
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not reach CipherOps API.'); }
    finally { setBusy(false); }
  }

  async function signInWithSso() {
    setError(''); setBusy(true);
    try {
      const response = await fetch(`${API}/auth/sso/start`); const data = await response.json();
      if (!response.ok) throw new Error(data.detail || 'Single sign-on could not start');
      window.location.assign(data.authorization_url);
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Single sign-on could not start'); setBusy(false); }
  }

  const screenTitle = ({ signin: 'Welcome back', signup: 'Create your account', forgot: 'Reset your password', reset: 'Choose a new password' })[screen];
  const screenSubtitle = ({ signin: 'Sign in to your security operations workspace.', signup: 'Create your analyst profile to join this workspace.', forgot: 'We will send a secure, one-time reset link if this email belongs to an account.', reset: 'Choose a new password for your CipherOps account.' })[screen];

  return <div className="login-screen"><div className="login-glow"/><main className={`login-card auth-card auth-${screen}`}>
    <div className="login-brand"><img src="/cipherops-icon.svg" alt=""/><span>CipherOps <b>AI</b></span></div>
    <div className="login-eyebrow"><i className="pulse-dot"/> SECURE WORKSPACE</div>
    <h1>{screenTitle}</h1><p className="auth-subtitle">{screenSubtitle}</p>

    {screen === 'signin' && <form onSubmit={submitSignIn}>
      <label className="auth-field"><span>Email address</span><input type="email" autoComplete="username" value={email} onChange={event => setEmail(event.target.value)} required/></label>
      <PasswordInput label="Password" autoComplete="current-password" value={password} onChange={setPassword}/>
      <label className="auth-field"><span>Authenticator code <small>Leave blank if MFA is not enabled</small></span><input inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={mfaCode} onChange={event => setMfaCode(event.target.value.replace(/\D/g, '').slice(0, 6))} placeholder="6-digit code"/></label>
      <div className="login-options"><label><input type="checkbox" checked={remember} onChange={event => setRemember(event.target.checked)}/> Remember this device</label><button type="button" className="auth-text-button" onClick={() => { setScreen('forgot'); setError(''); setMessage(''); }}>Forgot password?</button></div>
      {error && <div className="login-error">{error}</div>}{message && <div className="auth-message">{message}</div>}
      <button className="button primary login-submit" disabled={busy}>{busy ? 'Signing in…' : 'Sign in securely'} <ChevronRight size={15}/></button>
      {signupEnabled && <div className="auth-switch">New to CipherOps? <button type="button" onClick={() => { setScreen('signup'); setError(''); setMessage(''); }}>Create an account</button></div>}
    </form>}

    {screen === 'signup' && <form className="signup-form" onSubmit={submitSignup}>
      <div className="signup-avatar"><UserAvatar name={`${firstName} ${lastName}`} image={avatarData}/><div><strong>Profile photo</strong><small>Square crop · stored securely with your account</small><div className="avatar-actions"><label className="button secondary avatar-upload"><ImagePlus size={14}/> {avatarData ? 'Change photo' : 'Add photo'}<input type="file" accept="image/png,image/jpeg,image/webp" onChange={event => void chooseAvatar(event)}/></label>{avatarData && <button type="button" className="auth-text-button" onClick={() => setAvatarData(null)}><X size={13}/> Remove</button>}</div></div></div>
      <div className="auth-grid two"><label className="auth-field"><span>First name</span><input autoComplete="given-name" value={firstName} onChange={event => setFirstName(event.target.value)} maxLength={75} required/></label><label className="auth-field"><span>Last name</span><input autoComplete="family-name" value={lastName} onChange={event => setLastName(event.target.value)} maxLength={75} required/></label></div>
      <label className="auth-field"><span>Email address</span><input type="email" autoComplete="email" value={email} onChange={event => setEmail(event.target.value)} required/></label>
      <div className="auth-grid phone-grid"><CountryPicker label="Calling code" value={phoneCountry} onChange={choosePhoneCountry} showDialCode/><label className="auth-field"><span>Mobile number</span><input type="tel" autoComplete="tel-national" inputMode="tel" value={mobileNumber} onChange={event => setMobileNumber(event.target.value.replace(/\D/g, '').slice(0, 15))} placeholder="3001234567" minLength={6} maxLength={15} required/></label></div>
      <div className="auth-grid two"><CountryPicker label="Country" value={countryCode} onChange={selected => { setCountryCode(selected.code); setCountry(selected.name); }}/><label className="auth-field"><span>City</span><input autoComplete="address-level2" value={city} onChange={event => setCity(event.target.value)} maxLength={120} required/></label></div>
      <PasswordInput label="Password (12 characters minimum)" autoComplete="new-password" value={password} onChange={setPassword} minLength={12}/>
      <PasswordInput label="Confirm password" autoComplete="new-password" value={confirmPassword} onChange={setConfirmPassword} minLength={12}/>
      <div className="assigned-role"><ShieldCheck size={15}/><span>Workspace role</span><b>SOC Analyst</b><small>Workspace administrators assign elevated roles.</small></div>
      {error && <div className="login-error">{error}</div>}
      <button className="button primary login-submit" disabled={busy}>{busy ? 'Creating account…' : 'Create analyst account'} <ChevronRight size={15}/></button>
      <div className="auth-switch">Already have an account? <button type="button" onClick={() => { setScreen('signin'); setError(''); setMessage(''); }}>Sign in</button></div>
    </form>}

    {screen === 'forgot' && <form onSubmit={requestReset}>
      <label className="auth-field"><span>Email address</span><input type="email" autoComplete="email" value={email} onChange={event => setEmail(event.target.value)} required/></label>
      {error && <div className="login-error">{error}</div>}{message && <div className="auth-message">{message}{resetToken.startsWith('http') && <a className="dev-reset-link" href={resetToken}>Open local reset link <ChevronRight size={14}/></a>}</div>}
      <button className="button primary login-submit" disabled={busy}>{busy ? 'Preparing…' : 'Send reset link'} <ChevronRight size={15}/></button>
      <div className="auth-switch"><button type="button" onClick={() => { setScreen('signin'); setError(''); setMessage(''); setResetToken(''); }}>Back to sign in</button></div>
    </form>}

    {screen === 'reset' && <form onSubmit={submitReset}>
      {!resetToken && <label className="auth-field"><span>Reset token</span><input value={resetToken} onChange={event => setResetToken(event.target.value)} required/></label>}
      <PasswordInput label="New password (12 characters minimum)" autoComplete="new-password" value={password} onChange={setPassword} minLength={12}/>
      <PasswordInput label="Confirm new password" autoComplete="new-password" value={confirmPassword} onChange={setConfirmPassword} minLength={12}/>
      {error && <div className="login-error">{error}</div>}
      <button className="button primary login-submit" disabled={busy || !resetToken}>{busy ? 'Updating…' : 'Update password'} <ChevronRight size={15}/></button>
      <div className="auth-switch"><button type="button" onClick={() => { setScreen('signin'); setError(''); }}>Back to sign in</button></div>
    </form>}

    {screen === 'signin' && ssoEnabled && <><div className="login-divider"><span>OR</span></div><button className="button secondary login-submit" disabled={busy} onClick={() => void signInWithSso()}>{busy ? 'Connecting…' : 'Continue with company SSO'}</button></>}
    <div className="login-security"><ShieldCheck size={15}/><span>Encrypted session · Role-based access · Activity audited</span></div>
  </main><div className="login-footer">CIPHEROPS AI <span>·</span> AGENTIC CYBER DEFENSE</div></div>;
}
