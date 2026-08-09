import { FormEvent, lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react'

import { api } from './api'
import type { Asset, AuditEntry, FeedStatus, GraphData, SiteSummary } from './types'

const NetworkGraph = lazy(() =>
  import('./NetworkGraph').then((module) => ({ default: module.NetworkGraph })),
)

type View = 'inventory' | 'sites' | 'graph' | 'administration'

export default function App() {
  const [apiKey, setApiKey] = useState('')
  const [draftKey, setDraftKey] = useState('')
  const [assets, setAssets] = useState<Asset[]>([])
  const [graph, setGraph] = useState<GraphData>({ nodes: [], edges: [] })
  const [sites, setSites] = useState<SiteSummary[]>([])
  const [selected, setSelected] = useState<Asset | null>(null)
  const [view, setView] = useState<View>('inventory')
  const [query, setQuery] = useState('')
  const [siteFilter, setSiteFilter] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [inventoryAsOf, setInventoryAsOf] = useState(0)
  const [feedStatus, setFeedStatus] = useState<FeedStatus | null>(null)
  const [auditEvents, setAuditEvents] = useState<AuditEntry[] | null>(null)

  const refresh = useCallback(async (key: string) => {
    setLoading(true)
    setError('')
    try {
      const [assetRows, graphData, siteRows] = await Promise.all([api.assets(key), api.graph(key), api.sites(key)])
      setAssets(assetRows)
      setGraph(graphData)
      setSites(siteRows)
      setInventoryAsOf(Date.now())
      try {
        const [feeds, audit] = await Promise.all([api.feedStatus(key), api.audit(key)])
        setFeedStatus(feeds)
        setAuditEvents(audit)
      } catch {
        setFeedStatus(null)
        setAuditEvents(null)
        setView((current) => (current === 'administration' ? 'inventory' : current))
      }
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to load OT-Sentinel data.')
      throw reason
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (!apiKey) return
    const timer = window.setInterval(() => void refresh(apiKey).catch(() => undefined), 30_000)
    return () => window.clearInterval(timer)
  }, [apiKey, refresh])

  async function connect(event: FormEvent) {
    event.preventDefault()
    try {
      await refresh(draftKey)
      setApiKey(draftKey)
      setDraftKey('')
    } catch {
      setApiKey('')
    }
  }

  async function selectAsset(asset: Asset) {
    try {
      setSelected(await api.asset(apiKey, asset.id))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to load asset details.')
    }
  }

  async function runExport(exporter: (key: string) => Promise<void>) {
    try {
      setError('')
      await exporter(apiKey)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to generate export.')
    }
  }

  async function baselineFirmware(asset: Asset) {
    try {
      await api.setFirmwareBaseline(apiKey, asset.id)
      setSelected(await api.asset(apiKey, asset.id))
      await refresh(apiKey)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to set firmware baseline.')
    }
  }

  const visibleAssets = useMemo(() => {
    const needle = query.trim().toLocaleLowerCase()
    return assets.filter((asset) =>
      (!siteFilter || asset.site_id === siteFilter) && (!needle || [asset.ip_address, asset.hostname, asset.vendor, asset.model, ...asset.protocols]
        .filter(Boolean)
        .some((value) => String(value).toLocaleLowerCase().includes(needle))),
    )
  }, [assets, query, siteFilter])

  const staleCount = assets.filter(
    (asset) => inventoryAsOf - new Date(asset.last_seen).getTime() > 24 * 60 * 60 * 1000,
  ).length
  const driftCount = assets.filter((asset) => asset.firmware_drift).length

  if (!apiKey) {
    return <AccessGate draftKey={draftKey} setDraftKey={setDraftKey} connect={connect} error={error} />
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/95 px-5 py-4 backdrop-blur">
        <div className="mx-auto flex max-w-[1600px] items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="grid size-9 place-items-center rounded-md border border-emerald-500/40 bg-emerald-500/10 font-mono text-sm font-bold text-emerald-300">OT</div>
            <div>
              <h1 className="text-base font-semibold tracking-wide">OT-Sentinel</h1>
              <p className="text-xs text-slate-500">Passive asset and vulnerability management</p>
            </div>
          </div>
          <div className="flex items-center gap-3 text-xs">
            <span className="inline-flex items-center gap-2 text-emerald-300"><span className="size-2 rounded-full bg-emerald-400" />Connected</span>
            <button className="button-secondary hidden sm:block" onClick={() => void runExport(api.exportCsv)}>CSV</button>
            <button className="button-secondary hidden sm:block" onClick={() => void runExport(api.exportCycloneDx)}>CycloneDX</button>
            <button className="button-secondary" onClick={() => void refresh(apiKey).catch(() => undefined)} disabled={loading}>{loading ? 'Refreshing…' : 'Refresh'}</button>
            <button className="button-secondary" onClick={() => { setApiKey(''); setSelected(null) }}>Lock</button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-[1600px] px-5 py-6">
        {error && <div role="alert" className="mb-5 rounded-md border border-rose-500/30 bg-rose-500/10 px-4 py-3 text-sm text-rose-200">{error}</div>}
        <section className="mb-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-5" aria-label="Inventory summary">
          <Metric label="Observed assets" value={assets.length} detail="Across all configured sites" />
          <Metric label="Communication pairs" value={graph.edges.length} detail="Protocol-specific flows" />
          <Metric label="Stale assets" value={staleCount} detail="Not observed in 24 hours" warning={staleCount > 0} />
          <Metric label="Firmware drift" value={driftCount} detail="Observed version differs from baseline" warning={driftCount > 0} />
          <Metric label="Sites" value={new Set(assets.map((asset) => asset.site_id)).size} detail="Reporting inventory" />
        </section>

        <nav className="mb-4 flex gap-1 border-b border-slate-800" aria-label="Dashboard views">
          <Tab active={view === 'inventory'} onClick={() => setView('inventory')}>Asset inventory</Tab>
          <Tab active={view === 'sites'} onClick={() => setView('sites')}>Sites</Tab>
          <Tab active={view === 'graph'} onClick={() => setView('graph')}>Communication graph</Tab>
          {auditEvents && <Tab active={view === 'administration'} onClick={() => setView('administration')}>Administration</Tab>}
        </nav>

        {view === 'inventory' ? (
          <section className="panel overflow-hidden">
            <div className="flex flex-col gap-3 border-b border-slate-800 p-4 sm:flex-row sm:items-center sm:justify-between">
              <div><h2 className="font-medium">Asset inventory</h2><p className="mt-1 text-xs text-slate-500">Select an asset to review fingerprints and CVE matches.</p></div>
              <div className="flex w-full gap-2 sm:w-auto"><label className="sr-only" htmlFor="site-filter">Filter by site</label><select id="site-filter" className="input" value={siteFilter} onChange={(event) => setSiteFilter(event.target.value)}><option value="">All sites</option>{sites.map((site) => <option key={site.site_id} value={site.site_id}>{site.site_id}</option>)}</select><label className="sr-only" htmlFor="asset-search">Search assets</label><input id="asset-search" className="input w-full sm:w-80" placeholder="Search IP, vendor, model…" value={query} onChange={(event) => setQuery(event.target.value)} /></div>
            </div>
            <AssetTable assets={visibleAssets} selectAsset={selectAsset} />
          </section>
        ) : view === 'sites' ? (
          <SitesPanel sites={sites} openSite={(siteId) => { setSiteFilter(siteId); setView('inventory') }} />
        ) : view === 'graph' ? (
          <section className="panel overflow-hidden">
            <div className="border-b border-slate-800 p-4"><h2 className="font-medium">Observed communications</h2><p className="mt-1 text-xs text-slate-500">Edges reflect passively observed protocol traffic. Node placement has no physical-network meaning.</p></div>
            <Suspense fallback={<div className="grid h-[560px] place-items-center text-sm text-slate-500">Loading graph renderer…</div>}>
              <NetworkGraph data={graph} />
            </Suspense>
          </section>
        ) : (
          <AdministrationPanel feeds={feedStatus} events={auditEvents ?? []} />
        )}
      </main>
      {selected && <AssetDrawer asset={selected} close={() => setSelected(null)} canAdmin={auditEvents !== null} baselineFirmware={baselineFirmware} />}
    </div>
  )
}

function AccessGate({ draftKey, setDraftKey, connect, error }: { draftKey: string; setDraftKey: (value: string) => void; connect: (event: FormEvent) => void; error: string }) {
  return <main className="grid min-h-screen place-items-center bg-slate-950 p-5 text-slate-100"><form onSubmit={connect} className="panel w-full max-w-md p-7"><div className="mb-6 grid size-11 place-items-center rounded-md border border-emerald-500/40 bg-emerald-500/10 font-mono font-bold text-emerald-300">OT</div><h1 className="text-xl font-semibold">Access OT-Sentinel</h1><p className="mt-2 text-sm leading-6 text-slate-400">Enter an OIDC access token or an enabled bootstrap API key. The credential remains in memory and is cleared when this page closes.</p>{error && <p role="alert" className="mt-4 text-sm text-rose-300">{error}</p>}<label htmlFor="api-key" className="mt-6 block text-xs font-medium uppercase tracking-wider text-slate-400">Access token or API key</label><input id="api-key" type="password" autoComplete="off" required className="input mt-2 w-full" value={draftKey} onChange={(event) => setDraftKey(event.target.value)} /><button type="submit" className="button-primary mt-4 w-full">Connect securely</button></form></main>
}

function Metric({ label, value, detail, warning = false }: { label: string; value: number; detail: string; warning?: boolean }) {
  return <article className="panel p-4"><p className="text-xs font-medium uppercase tracking-wider text-slate-500">{label}</p><p className={`mt-2 font-mono text-2xl font-semibold ${warning ? 'text-amber-300' : 'text-slate-100'}`}>{value}</p><p className="mt-1 text-xs text-slate-500">{detail}</p></article>
}

function Tab({ active, onClick, children }: { active: boolean; onClick: () => void; children: string }) {
  return <button onClick={onClick} aria-current={active ? 'page' : undefined} className={`border-b-2 px-4 py-3 text-sm ${active ? 'border-emerald-400 text-emerald-300' : 'border-transparent text-slate-400 hover:text-slate-200'}`}>{children}</button>
}

function AssetTable({ assets, selectAsset }: { assets: Asset[]; selectAsset: (asset: Asset) => void }) {
  if (assets.length === 0) return <p className="p-10 text-center text-sm text-slate-500">No assets match the current view.</p>
  return <div className="overflow-x-auto"><table className="w-full text-left text-sm"><thead className="bg-slate-900/60 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-4 py-3">Address</th><th className="px-4 py-3">Identity</th><th className="px-4 py-3">Protocols</th><th className="px-4 py-3">Site</th><th className="px-4 py-3">Last seen</th><th className="px-4 py-3"><span className="sr-only">Open</span></th></tr></thead><tbody className="divide-y divide-slate-800">{assets.map((asset) => <tr key={asset.id} className="hover:bg-slate-900/70"><td className="px-4 py-3 font-mono text-emerald-300">{asset.ip_address}<span className="mt-1 block text-xs text-slate-600">{asset.mac_address ?? 'MAC unknown'}</span></td><td className="px-4 py-3">{[asset.vendor, asset.model].filter(Boolean).join(' ') || asset.hostname || 'Unidentified device'}<span className="mt-1 block text-xs text-slate-500">{asset.firmware_version ? `Firmware ${asset.firmware_version}` : 'Firmware unknown'}</span></td><td className="px-4 py-3"><div className="flex flex-wrap gap-1">{asset.protocols.map((protocol) => <span key={protocol} className="badge">{protocol}</span>)}</div></td><td className="px-4 py-3 text-slate-400">{asset.site_id}</td><td className="px-4 py-3 text-slate-400">{formatTime(asset.last_seen)}</td><td className="px-4 py-3"><button className="text-emerald-300 hover:text-emerald-200" onClick={() => void selectAsset(asset)}>Review</button></td></tr>)}</tbody></table></div>
}

function SitesPanel({ sites, openSite }: { sites: SiteSummary[]; openSite: (siteId: string) => void }) {
  if (sites.length === 0) return <section className="panel p-10 text-center text-sm text-slate-500">No sites are reporting inventory.</section>
  return <section className="panel overflow-hidden"><div className="border-b border-slate-800 p-4"><h2 className="font-medium">Site overview</h2><p className="mt-1 text-xs text-slate-500">Aggregated operational exposure across reporting locations.</p></div><div className="grid gap-4 p-4 md:grid-cols-2 xl:grid-cols-3">{sites.map((site) => <article key={site.site_id} className="rounded-md border border-slate-800 bg-slate-900/40 p-4"><div className="flex items-start justify-between gap-3"><div><h3 className="font-mono font-semibold text-emerald-300">{site.site_id}</h3><p className="mt-1 text-xs text-slate-500">Last seen {formatTime(site.last_seen)}</p></div><button className="button-secondary" onClick={() => openSite(site.site_id)}>Open inventory</button></div><dl className="mt-4 grid grid-cols-2 gap-3"><Fact label="Assets" value={String(site.asset_count)} /><Fact label="Vulnerable assets" value={String(site.vulnerable_assets)} /><Fact label="CVE matches" value={String(site.vulnerability_matches)} /><Fact label="Firmware drift" value={String(site.firmware_drift_count)} /></dl></article>)}</div></section>
}

function AssetDrawer({ asset, close, canAdmin, baselineFirmware }: { asset: Asset; close: () => void; canAdmin: boolean; baselineFirmware: (asset: Asset) => Promise<void> }) {
  const vulnerabilities = asset.vulnerabilities ?? []
  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === 'Escape') close()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [close])
  return <div className="fixed inset-0 z-20 flex justify-end bg-black/60" role="dialog" aria-modal="true" aria-label={`Asset ${asset.ip_address}`} onMouseDown={(event) => { if (event.target === event.currentTarget) close() }}><aside className="h-full w-full max-w-xl overflow-y-auto border-l border-slate-700 bg-slate-950 shadow-2xl"><div className="sticky top-0 flex items-start justify-between border-b border-slate-800 bg-slate-950/95 p-5 backdrop-blur"><div><p className="font-mono text-lg text-emerald-300">{asset.ip_address}</p><p className="mt-1 text-sm text-slate-400">{[asset.vendor, asset.model].filter(Boolean).join(' ') || 'Unidentified OT asset'}</p></div><button onClick={close} className="button-secondary" aria-label="Close asset details">Close</button></div><div className="space-y-6 p-5"><section><div className="flex items-center justify-between gap-3"><h3 className="section-title">Asset evidence</h3>{asset.firmware_drift && <span className="badge-danger">Firmware drift</span>}</div><dl className="mt-3 grid grid-cols-2 gap-3 text-sm"><Fact label="Site" value={asset.site_id} /><Fact label="Firmware" value={asset.firmware_version ?? 'Unknown'} /><Fact label="Baseline" value={asset.firmware_baseline ?? 'Not set'} /><Fact label="First seen" value={formatTime(asset.first_seen)} /><Fact label="Last seen" value={formatTime(asset.last_seen)} /></dl>{canAdmin && asset.firmware_version && <button className="button-secondary mt-3" onClick={() => void baselineFirmware(asset)}>Set current firmware as baseline</button>}</section><section><h3 className="section-title">Vulnerability matches <span className="ml-2 text-slate-500">{vulnerabilities.length}</span></h3><div className="mt-3 space-y-3">{vulnerabilities.length === 0 ? <p className="rounded-md border border-slate-800 p-4 text-sm text-slate-500">No CVE matches are currently associated with this fingerprint.</p> : vulnerabilities.map((item) => <article key={item.cve_id} className="rounded-md border border-slate-800 bg-slate-900/50 p-4"><div className="flex items-center justify-between gap-3"><span className="font-mono text-sm font-semibold text-slate-100">{item.cve_id}</span><span className={item.known_exploited ? 'badge-danger' : 'badge'}>{item.known_exploited ? 'Known exploited' : item.severity ?? 'Unscored'}</span></div><p className="mt-3 line-clamp-3 text-sm leading-6 text-slate-400">{item.advisory.description || 'No English description available.'}</p><div className="mt-3 flex gap-4 text-xs text-slate-500"><span>CVSS {item.cvss_score ?? '—'}</span><span>{item.status}</span><span>{Math.round(item.confidence * 100)}% confidence</span></div></article>)}</div></section></div></aside></div>
}

function AdministrationPanel({ feeds, events }: { feeds: FeedStatus | null; events: AuditEntry[] }) {
  return <div className="grid gap-5 xl:grid-cols-[360px_1fr]"><section className="panel p-5"><h2 className="font-medium">Vulnerability feeds</h2><p className="mt-1 text-xs text-slate-500">Latest audited offline import state.</p><div className="mt-4 space-y-3">{!feeds || feeds.sources.length === 0 ? <p className="text-sm text-slate-500">No feed imports have been recorded.</p> : feeds.sources.map((source) => <article key={source.source} className="rounded-md border border-slate-800 p-3"><div className="flex items-center justify-between gap-3"><span className="font-mono text-sm">{source.source}</span><span className={source.status === 'healthy' ? 'badge' : 'badge-danger'}>{source.status}</span></div><p className="mt-2 text-xs text-slate-500">{formatTime(source.occurred_at)}</p></article>)}</div></section><section className="panel overflow-hidden"><div className="border-b border-slate-800 p-5"><h2 className="font-medium">Immutable audit activity</h2><p className="mt-1 text-xs text-slate-500">Most recent authenticated and sensor actions. Hashes support independent chain verification.</p></div><div className="max-h-[650px] overflow-auto"><table className="w-full text-left text-sm"><thead className="sticky top-0 bg-slate-900 text-xs uppercase tracking-wider text-slate-500"><tr><th className="px-4 py-3">Time</th><th className="px-4 py-3">Actor</th><th className="px-4 py-3">Action</th><th className="px-4 py-3">Object</th><th className="px-4 py-3">Hash</th></tr></thead><tbody className="divide-y divide-slate-800">{events.map((event) => <tr key={event.id}><td className="whitespace-nowrap px-4 py-3 text-slate-400">{formatTime(event.occurred_at)}</td><td className="px-4 py-3 text-slate-300">{event.actor_subject ?? 'system'}</td><td className="px-4 py-3 font-mono text-emerald-300">{event.action}</td><td className="px-4 py-3 text-slate-400">{event.object_type}{event.object_id ? ` · ${event.object_id}` : ''}</td><td className="px-4 py-3 font-mono text-xs text-slate-500" title={event.entry_hash}>{event.entry_hash.slice(0, 12)}…</td></tr>)}</tbody></table></div></section></div>
}

function Fact({ label, value }: { label: string; value: string }) { return <div className="rounded-md bg-slate-900/60 p-3"><dt className="text-xs text-slate-500">{label}</dt><dd className="mt-1 break-words text-slate-200">{value}</dd></div> }
function formatTime(value: string) { return new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value)) }
