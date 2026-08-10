import { FormEvent, useState } from 'react'

import { api } from './api'
import type { AdminControls as Controls } from './types'

const BASELINE_CONFIRMATION = 'CAPTURE CURRENT COMMUNICATIONS AS BASELINE'
const PROBE_CONFIRMATION = 'I APPROVE CONTROLLED ACTIVE PROBING'

export function AdminControls({ apiKey, controls, refresh, reportError }: { apiKey: string; controls: Controls; refresh: () => Promise<void>; reportError: (message: string) => void }) {
  const [busy, setBusy] = useState(false)
  const [alertName, setAlertName] = useState('')
  const [alertEvent, setAlertEvent] = useState('communication_anomaly')
  const [alertSite, setAlertSite] = useState('')
  const [webhookUrl, setWebhookUrl] = useState('')
  const [siemName, setSiemName] = useState('')
  const [siemHost, setSiemHost] = useState('')
  const [siemPort, setSiemPort] = useState(6514)
  const [siemSeverity, setSiemSeverity] = useState('medium')
  const [baselineSite, setBaselineSite] = useState('')
  const [baselineConfirmation, setBaselineConfirmation] = useState('')
  const [probeName, setProbeName] = useState('')
  const [probeSite, setProbeSite] = useState('')
  const [probeCidrs, setProbeCidrs] = useState('')
  const [probePolicyId, setProbePolicyId] = useState('')
  const [probeConfirmation, setProbeConfirmation] = useState('')
  const [approvalHours, setApprovalHours] = useState(4)

  async function run(operation: () => Promise<unknown>) {
    setBusy(true)
    reportError('')
    try {
      await operation()
      await refresh()
    } catch (reason) {
      reportError(reason instanceof Error ? reason.message : 'Administrative operation failed.')
    } finally {
      setBusy(false)
    }
  }

  function submitAlert(event: FormEvent) {
    event.preventDefault()
    void run(async () => {
      await api.createAlertRule(apiKey, { name: alertName, event_type: alertEvent, site_id: alertSite || null, webhook_url: webhookUrl })
      setAlertName(''); setWebhookUrl('')
    })
  }

  function submitSiem(event: FormEvent) {
    event.preventDefault()
    void run(async () => {
      await api.createSiemDestination(apiKey, { name: siemName, host: siemHost, port: siemPort, minimum_severity: siemSeverity })
      setSiemName(''); setSiemHost('')
    })
  }

  function submitBaseline(event: FormEvent) {
    event.preventDefault()
    void run(async () => {
      await api.captureBaseline(apiKey, baselineSite, baselineConfirmation)
      setBaselineConfirmation('')
    })
  }

  function submitProbe(event: FormEvent) {
    event.preventDefault()
    void run(async () => {
      await api.createProbePolicy(apiKey, {
        name: probeName,
        site_id: probeSite,
        allowed_cidrs: probeCidrs.split(',').map((value) => value.trim()).filter(Boolean),
        protocols: ['icmp_echo'],
        max_targets: 16,
        rate_per_minute: 6,
        maintenance_start_hour: 0,
        maintenance_end_hour: 0,
      })
      setProbeName(''); setProbeCidrs('')
    })
  }

  function approveProbe(event: FormEvent) {
    event.preventDefault()
    void run(async () => {
      await api.approveProbePolicy(apiKey, probePolicyId, probeConfirmation, approvalHours)
      setProbeConfirmation('')
    })
  }

  return <div className="space-y-5">
    <section className="panel p-5"><h2 className="font-medium">Security integrations</h2><p className="mt-1 text-xs text-slate-500">Destinations are validated by the API. TLS Syslog destinations are disabled until explicitly enabled.</p><div className="mt-5 grid gap-5 xl:grid-cols-2">
      <div><h3 className="section-title">Webhook alert rules</h3><form onSubmit={submitAlert} className="mt-3 grid gap-2 sm:grid-cols-2"><input required className="input" placeholder="Rule name" value={alertName} onChange={(event) => setAlertName(event.target.value)} /><select className="input" value={alertEvent} onChange={(event) => setAlertEvent(event.target.value)}><option value="communication_anomaly">Communication anomaly</option><option value="firmware_drift">Firmware drift</option><option value="vulnerability_match">Vulnerability match</option></select><input className="input" placeholder="Site (blank for all)" value={alertSite} onChange={(event) => setAlertSite(event.target.value)} /><input required type="url" className="input" placeholder="https://collector.example/hook" value={webhookUrl} onChange={(event) => setWebhookUrl(event.target.value)} /><button disabled={busy} className="button-primary sm:col-span-2">Create webhook rule</button></form><div className="mt-3 space-y-2">{controls.alertRules.map((rule) => <div key={rule.id} className="flex items-center justify-between rounded-md border border-slate-800 p-3 text-sm"><div><span className="font-medium">{rule.name}</span><span className="ml-2 text-xs text-slate-500">{rule.event_type} · {rule.site_id ?? 'all sites'}</span></div><button disabled={busy} className="text-rose-300" onClick={() => void run(() => api.deleteAlertRule(apiKey, rule.id))}>Delete</button></div>)}</div></div>
      <div><h3 className="section-title">TLS Syslog destinations</h3><form onSubmit={submitSiem} className="mt-3 grid gap-2 sm:grid-cols-2"><input required className="input" placeholder="Destination name" value={siemName} onChange={(event) => setSiemName(event.target.value)} /><input required className="input" placeholder="siem.example.com" value={siemHost} onChange={(event) => setSiemHost(event.target.value)} /><input required type="number" min="1" max="65535" className="input" value={siemPort} onChange={(event) => setSiemPort(Number(event.target.value))} /><select className="input" value={siemSeverity} onChange={(event) => setSiemSeverity(event.target.value)}><option value="info">Info</option><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select><button disabled={busy} className="button-primary sm:col-span-2">Create disabled destination</button></form><div className="mt-3 space-y-2">{controls.siemDestinations.map((item) => <div key={item.id} className="flex items-center justify-between rounded-md border border-slate-800 p-3 text-sm"><div><span className="font-medium">{item.name}</span><span className="ml-2 text-xs text-slate-500">{item.host}:{item.port} · {item.minimum_severity}+</span></div><button disabled={busy} className={item.enabled ? 'text-rose-300' : 'text-emerald-300'} onClick={() => void run(() => api.setSiemEnabled(apiKey, item.id, !item.enabled))}>{item.enabled ? 'Disable' : 'Enable'}</button></div>)}</div></div>
    </div></section>

    <section className="grid gap-5 xl:grid-cols-2"><div className="panel p-5"><h2 className="font-medium">Communication baselines</h2><p className="mt-1 text-xs text-slate-500">Capture only after observing a representative known-good operating cycle.</p><form onSubmit={submitBaseline} className="mt-4 space-y-2"><input required className="input w-full" placeholder="Site ID" value={baselineSite} onChange={(event) => setBaselineSite(event.target.value)} /><label className="block text-xs text-slate-500">Type <span className="font-mono text-amber-300">{BASELINE_CONFIRMATION}</span></label><input required className="input w-full" value={baselineConfirmation} onChange={(event) => setBaselineConfirmation(event.target.value)} /><button disabled={busy || baselineConfirmation !== BASELINE_CONFIRMATION} className="button-primary w-full">Capture baseline</button></form><div className="mt-4 space-y-2">{controls.baselines.slice(0, 10).map((item) => <div key={item.id} className="rounded-md border border-slate-800 p-3 text-sm"><span className={item.active ? 'badge' : 'badge-danger'}>{item.active ? 'active' : 'superseded'}</span><span className="ml-2">{item.site_id}</span><span className="ml-2 text-xs text-slate-500">{item.edge_count} edges</span></div>)}</div></div>

      <div className="panel p-5"><h2 className="font-medium">Active-probing policies</h2><p className="mt-1 text-xs text-slate-500">Global gate: {controls.probeStatus.global_enabled ? 'enabled' : 'disabled'} · Executor: not installed · Transmission capable: no</p><form onSubmit={submitProbe} className="mt-4 grid gap-2 sm:grid-cols-2"><input required className="input" placeholder="Policy name" value={probeName} onChange={(event) => setProbeName(event.target.value)} /><input required className="input" placeholder="Site ID" value={probeSite} onChange={(event) => setProbeSite(event.target.value)} /><input required className="input sm:col-span-2" placeholder="Exact CIDRs, comma separated" value={probeCidrs} onChange={(event) => setProbeCidrs(event.target.value)} /><button disabled={busy} className="button-primary sm:col-span-2">Create disabled policy</button></form><form onSubmit={approveProbe} className="mt-4 space-y-2"><select required className="input w-full" value={probePolicyId} onChange={(event) => setProbePolicyId(event.target.value)}><option value="">Select policy to approve</option>{controls.probeStatus.policies.filter((item) => !item.enabled).map((item) => <option key={item.id} value={item.id}>{item.name} · {item.site_id}</option>)}</select><label className="block text-xs text-slate-500">Type <span className="font-mono text-amber-300">{PROBE_CONFIRMATION}</span></label><input required className="input w-full" value={probeConfirmation} onChange={(event) => setProbeConfirmation(event.target.value)} /><input type="number" min="1" max="24" className="input w-full" value={approvalHours} onChange={(event) => setApprovalHours(Number(event.target.value))} /><button disabled={busy || !probePolicyId || probeConfirmation !== PROBE_CONFIRMATION} className="button-primary w-full">Approve temporarily</button></form><div className="mt-4 space-y-2">{controls.probeStatus.policies.map((item) => <div key={item.id} className="flex items-center justify-between rounded-md border border-slate-800 p-3 text-sm"><div><span className="font-medium">{item.name}</span><span className="ml-2 text-xs text-slate-500">{item.site_id} · {item.allowed_cidrs.join(', ')}</span></div>{item.enabled && <button disabled={busy} className="text-rose-300" onClick={() => void run(() => api.disableProbePolicy(apiKey, item.id))}>Disable</button>}</div>)}</div></div>
    </section>
  </div>
}
