import { useCallback, useEffect, useState } from 'react';
import { Activity, ChevronRight, RefreshCw, Search, ShieldCheck, Siren } from 'lucide-react';
import { Badge } from '../components/Badge';
import { api } from '../shared';

type AlertRecord = {
  alert_key: string; title: string; description: string; severity: string; status: string;
  source: string; external_id: string | null; asset_key: string | null; assigned_to: string;
  first_seen: string; last_seen: string;
};

export function AlertsPage({ token, onIncident, initialQuery = '' }: { token: string; onIncident: (key?: string) => void; initialQuery?: string }) {
  const [alerts, setAlerts] = useState<AlertRecord[]>([]);
  const [query, setQuery] = useState(initialQuery);
  useEffect(() => { setQuery(initialQuery); }, [initialQuery]);
  const [error, setError] = useState('');
  const [busyKey, setBusyKey] = useState('');
  const refresh = useCallback(async () => {
    try { setAlerts(await api<AlertRecord[]>('/alerts?limit=250', token)); setError(''); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not load alerts'); }
  }, [token]);
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 15000); return () => window.clearInterval(timer); }, [refresh]);

  async function update(alert: AlertRecord, patch: { status?: string; assigned_to?: string }) {
    setBusyKey(alert.alert_key); setError('');
    try { await api(`/alerts/${alert.alert_key}`, token, { method: 'PATCH', body: JSON.stringify(patch) }); await refresh(); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not update alert'); }
    finally { setBusyKey(''); }
  }
  async function assign(alert: AlertRecord) {
    const value = window.prompt('Assign alert to:', alert.assigned_to === 'Unassigned' ? '' : alert.assigned_to);
    if (!value?.trim()) return;
    await update(alert, { assigned_to: value.trim() });
  }
  async function promote(alert: AlertRecord) {
    setBusyKey(alert.alert_key); setError('');
    try { const incident = await api<{ incident_key: string }>(`/alerts/${alert.alert_key}/promote`, token, { method: 'POST' }); onIncident(incident.incident_key); }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not create incident'); }
    finally { setBusyKey(''); }
  }
  const visibleAlerts = alerts.filter((alert) => `${alert.alert_key} ${alert.title} ${alert.source} ${alert.asset_key || ''} ${alert.assigned_to}`.toLowerCase().includes(query.toLowerCase()));
  const openCount = alerts.filter((alert) => !['Resolved', 'Suppressed'].includes(alert.status)).length;
  return <>
    <div className="page-head"><div><div className="eyebrow">SECURITY OPERATIONS / ALERT TRIAGE</div><h1>Alerts</h1><p className="subtitle">Persistent detections normalized from your integrations. Refreshes every 15 seconds.</p></div><button className="button secondary" onClick={() => void refresh()}><RefreshCw size={14}/> Refresh</button></div>
    <div className="module-metrics"><div className="panel module-stat"><span>Open alerts</span><strong>{openCount}</strong><small>Awaiting analyst disposition</small></div><div className="panel module-stat"><span>Critical</span><strong className="text-red">{alerts.filter((item) => item.severity === 'Critical' && item.status !== 'Resolved').length}</strong><small>Unresolved critical alerts</small></div><div className="panel module-stat"><span>Sources reporting</span><strong>{new Set(alerts.map((item) => item.source)).size}</strong><small>Integration feeds</small></div><div className="panel module-stat"><span>Total alerts</span><strong>{alerts.length}</strong><small>Latest seen first</small></div></div>
    {error && <div className="admin-error">{error}</div>}
    <section className="panel list-panel"><div className="panel-head"><div><h2>Alert queue</h2><p>Assign, acknowledge, resolve, or promote an alert into an investigation.</p></div><Badge tone="blue"><Activity size={12}/> Live</Badge></div><div className="filters"><label className="search"><Search size={15}/><input placeholder="Search alerts…" value={query} onChange={event=>setQuery(event.target.value)}/></label><span className="spacer"/><span>{visibleAlerts.length} of {alerts.length}</span></div><div className="table-wrap"><table><thead><tr>{['ALERT','SEVERITY','SOURCE','ASSET','ASSIGNEE','STATUS','LAST SEEN','ACTIONS'].map((x) => <th key={x}>{x}</th>)}</tr></thead><tbody>{visibleAlerts.map((alert) => <tr key={alert.alert_key}><td><div className="incident-title"><i className={'incident-dot '+(alert.severity === 'Critical' ? 'red' : 'amber')}/><div><strong>{alert.title}</strong><small>{alert.alert_key} · {alert.external_id || 'No source ID'}</small></div></div></td><td><Badge tone={alert.severity === 'Critical' ? 'red' : alert.severity === 'High' ? 'amber' : 'blue'}>{alert.severity}</Badge></td><td>{alert.source}</td><td>{alert.asset_key || '—'}</td><td>{alert.assigned_to}</td><td><select className="inline-select" disabled={busyKey === alert.alert_key} value={alert.status} onChange={(event) => void update(alert, { status: event.target.value })}>{['New', 'Acknowledged', 'Investigating', 'Resolved', 'Suppressed'].map((status) => <option key={status}>{status}</option>)}</select></td><td>{new Date(alert.last_seen).toLocaleString()}</td><td><div className="alert-actions"><button className="button secondary" disabled={busyKey === alert.alert_key} onClick={() => void assign(alert)}>Assign</button><button className="button primary" disabled={busyKey === alert.alert_key} title="Create an incident from this alert" onClick={() => void promote(alert)}><Siren size={13}/><span className="sr-only">Promote to incident</span><ChevronRight size={13}/></button></div></td></tr>)}</tbody></table>{visibleAlerts.length === 0 && <div className="empty-state"><ShieldCheck size={24}/><strong>{alerts.length===0?'No alerts received':'No matching alerts'}</strong><span>{alerts.length===0?'Configure an ingestion integration to send detections.':'Try a different search term.'}</span></div>}</div></section>
  </>;
}
