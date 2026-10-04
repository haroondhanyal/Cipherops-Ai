import { useCallback, useEffect, useState } from 'react';
import { Boxes, RefreshCw, Search } from 'lucide-react';
import { Badge } from '../components/Badge';
import { api } from '../shared';

type AssetRecord = { asset_key: string; name: string; asset_type: string; environment: string; provider: string; region: string; owner: string; criticality: string; risk_score: number; status: string; first_seen: string; last_seen: string };
export function AssetsPage({ token, initialQuery = '' }: { token: string; initialQuery?: string }) {
  const [assets, setAssets] = useState<AssetRecord[]>([]); const [query, setQuery] = useState(initialQuery); const [error, setError] = useState('');
  const refresh = useCallback(async () => { try { setAssets(await api<AssetRecord[]>(`/assets?limit=500${query ? `&query=${encodeURIComponent(query)}` : ''}`, token)); setError(''); } catch (reason) { setError(reason instanceof Error ? reason.message : 'Could not load assets'); } }, [token, query]);
  useEffect(() => { setQuery(initialQuery); }, [initialQuery]);
  useEffect(() => { void refresh(); const timer = window.setInterval(() => void refresh(), 15000); return () => window.clearInterval(timer); }, [refresh]);
  const critical = assets.filter((asset) => asset.criticality === 'Critical').length;
  const highRisk = assets.filter((asset) => asset.risk_score >= 70).length;
  return <>
    <div className="page-head"><div><div className="eyebrow">SECURITY OPERATIONS / INVENTORY</div><h1>Assets</h1><p className="subtitle">Discovered infrastructure normalized from incoming telemetry. Inventory syncs every 15 seconds.</p></div><button className="button secondary" onClick={() => void refresh()}><RefreshCw size={14}/> Refresh</button></div>
    <div className="module-metrics"><div className="panel module-stat"><span>Monitored assets</span><strong>{assets.length}</strong><small>Persisted inventory</small></div><div className="panel module-stat"><span>Critical assets</span><strong className="text-red">{critical}</strong><small>Business criticality</small></div><div className="panel module-stat"><span>High risk</span><strong className="text-amber">{highRisk}</strong><small>Risk score 70 or higher</small></div><div className="panel module-stat"><span>Providers</span><strong>{new Set(assets.map((asset) => asset.provider)).size}</strong><small>Connected sources</small></div></div>
    {error && <div className="admin-error">{error}</div>}
    <section className="panel list-panel"><div className="filters"><label className="search"><Search size={15}/><input placeholder="Search assets or identifiers..." value={query} onChange={(event) => setQuery(event.target.value)}/></label><span className="spacer"/><span className="muted-caption">Updated from telemetry feeds</span></div><div className="table-wrap"><table><thead><tr>{['ASSET','TYPE','PROVIDER','ENVIRONMENT','REGION','OWNER','CRITICALITY','RISK','LAST SEEN'].map((x) => <th key={x}>{x}</th>)}</tr></thead><tbody>{assets.map((asset) => <tr key={asset.asset_key}><td><div className="incident-title"><span className="metric-icon blue"><Boxes size={14}/></span><div><strong>{asset.name}</strong><small>{asset.asset_key}</small></div></div></td><td>{asset.asset_type}</td><td>{asset.provider}</td><td>{asset.environment}</td><td>{asset.region}</td><td>{asset.owner}</td><td><Badge tone={asset.criticality === 'Critical' ? 'red' : asset.criticality === 'High' ? 'amber' : 'blue'}>{asset.criticality}</Badge></td><td><span className={asset.risk_score >= 70 ? 'text-amber' : ''}>{asset.risk_score}</span></td><td>{new Date(asset.last_seen).toLocaleString()}</td></tr>)}</tbody></table>{assets.length === 0 && <div className="empty-state"><Boxes size={24}/><strong>Asset inventory is empty</strong><span>Create an integration and include an asset in telemetry events.</span></div>}</div></section>
  </>;
}
