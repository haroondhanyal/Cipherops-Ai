import { useCallback, useEffect, useState, type FormEvent } from 'react';
import { Activity, Plus } from 'lucide-react';
import { Badge } from '../components/Badge';
import { api } from '../shared';

type Role = { name: string; description: string; permissions: string[] };
type UserRow = { id: number; email: string; full_name: string; is_active: boolean; roles: string[]; requested_role?: string | null };
type AuditRow = { id: number; actor_id: number | null; action: string; resource: string; created_at: string };

export function AdminPage({ token, view }: { token: string; view: 'Users' | 'Roles' | 'Audit Logs' }) {
  const [users, setUsers] = useState<UserRow[]>([]);
  const [roles, setRoles] = useState<Role[]>([]);
  const [logs, setLogs] = useState<AuditRow[]>([]);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [role, setRole] = useState('SOC Analyst');

  const refresh = useCallback(async () => {
    setError('');
    try {
      if (view === 'Users') {
        const [userRows, roleRows] = await Promise.all([api<UserRow[]>('/admin/users', token), api<Role[]>('/admin/roles', token)]);
        setUsers(userRows); setRoles(roleRows);
      }
      if (view === 'Roles') setRoles(await api<Role[]>('/admin/roles', token));
      if (view === 'Audit Logs') setLogs(await api<AuditRow[]>('/admin/audit-logs', token));
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not load administration data'); }
  }, [token, view]);

  useEffect(() => { void refresh(); }, [refresh]);

  async function createUser(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      await api('/admin/users', token, { method: 'POST', body: JSON.stringify({ email, full_name: name, password, role }) });
      setEmail(''); setName(''); setPassword(''); await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not create user'); }
    finally { setBusy(false); }
  }

  async function toggleUser(user: UserRow) {
    try { await api(`/admin/users/${user.id}`, token, { method: 'PATCH', body: JSON.stringify({ is_active: !user.is_active }) }); await refresh(); }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not update user'); }
  }

  async function assignRole(user: UserRow, nextRole: string) {
    try {
      await api(`/admin/users/${user.id}/role`, token, { method: 'PATCH', body: JSON.stringify({ role: nextRole }) });
      await refresh();
    } catch (cause) { setError(cause instanceof Error ? cause.message : 'Could not assign role'); }
  }

  return <>
    <div className="page-head"><div><div className="eyebrow">ADMINISTRATION / ACCESS CONTROL</div><h1>{view}</h1><p className="subtitle">Manage workspace access with role based permissions and auditable changes.</p></div><button className="button secondary" onClick={() => void refresh()}><Activity size={14}/> Refresh</button></div>
    {error && <div className="admin-error">{error}{error.includes('permission') || error.includes('permissions') ? ' · Ask a Security Administrator to grant access.' : ''}</div>}
    {view === 'Users' && <>
      <div className="panel admin-create"><h2>Create a user</h2><p>New passwords must contain at least 12 characters.</p><form onSubmit={event => void createUser(event)}><input type="text" placeholder="Full name" value={name} onChange={event => setName(event.target.value)} required minLength={2}/><input type="email" placeholder="Work email" value={email} onChange={event => setEmail(event.target.value)} required/><input type="password" placeholder="Temporary password (12+ characters)" value={password} onChange={event => setPassword(event.target.value)} required minLength={12}/><select value={role} onChange={event => setRole(event.target.value)}>{roles.map(item => <option key={item.name}>{item.name}</option>)}</select><button className="button primary" disabled={busy}><Plus size={14}/>{busy ? 'Creating…' : 'Create user'}</button></form></div>
      <div className="panel list-panel admin-table"><table><thead><tr>{['USER', 'EMAIL', 'ROLE / REQUEST', 'STATUS', 'ACTION'].map(item => <th key={item}>{item}</th>)}</tr></thead><tbody>{users.map(user => <tr key={user.id}><td>{user.full_name}</td><td>{user.email}</td><td><div>{user.roles.join(', ')}</div>{user.requested_role && user.requested_role !== user.roles[0] && <small className="role-request">Requested: {user.requested_role}</small>}<select aria-label={`Assign role to ${user.email}`} value={user.roles[0] || 'SOC Analyst'} onChange={event => void assignRole(user, event.target.value)}>{roles.map(item => <option key={item.name}>{item.name}</option>)}</select></td><td><Badge tone={user.is_active ? 'blue' : 'red'}>{user.is_active ? 'Active' : 'Disabled'}</Badge></td><td><button className="button secondary" onClick={() => void toggleUser(user)}>{user.is_active ? 'Deactivate' : 'Activate'}</button></td></tr>)}</tbody></table></div>
    </>}
    {view === 'Roles' && <div className="panel list-panel admin-table"><table><thead><tr>{['ROLE', 'DESCRIPTION', 'PERMISSIONS'].map(item => <th key={item}>{item}</th>)}</tr></thead><tbody>{roles.map(item => <tr key={item.name}><td>{item.name}</td><td>{item.description}</td><td><div className="permission-list">{item.permissions.map(permission => <Badge key={permission} tone="blue">{permission}</Badge>)}</div></td></tr>)}</tbody></table></div>}
    {view === 'Audit Logs' && <div className="panel list-panel admin-table"><table><thead><tr>{['TIME', 'ACTOR ID', 'ACTION', 'RESOURCE'].map(item => <th key={item}>{item}</th>)}</tr></thead><tbody>{logs.map(log => <tr key={log.id}><td>{new Date(log.created_at).toLocaleString()}</td><td>{log.actor_id ?? 'System'}</td><td>{log.action}</td><td>{log.resource}</td></tr>)}</tbody></table></div>}
  </>;
}
