import { useState } from 'react'

type Device = { id: string; label: string; running: boolean }
const initialDevices: Device[] = [
  { id: 'P-101', label: 'Cooling circulation pump', running: true },
  { id: 'P-102', label: 'Backup circulation pump', running: false },
  { id: 'F-201', label: 'Ventilation fan', running: true },
]

export function PublicSimulator({ onExit }: { onExit: () => void }) {
  const [devices, setDevices] = useState<Device[]>(initialDevices)
  const [events, setEvents] = useState<string[]>(['Synthetic simulation initialized'])
  const toggle = (id: string) => {
    const device = devices.find((item) => item.id === id)
    if (!device) return
    setDevices((current) => current.map((item) => item.id === id ? { ...item, running: !item.running } : item))
    setEvents((current) => [`${id} simulated ${device.running ? 'stop' : 'start'}`, ...current].slice(0, 8))
  }
  const reset = () => {
    setDevices(initialDevices)
    setEvents(['Synthetic simulation reset'])
  }
  return <main className="min-h-screen bg-slate-950 p-5 text-slate-100">
    <div className="mx-auto max-w-5xl space-y-6">
      <header className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-5">
        <div><h1 className="text-2xl font-semibold">OT-Sentinel · Public Simulator</h1><p className="mt-1 text-sm text-slate-400">Educational synthetic process model · no login required</p></div>
        <button type="button" className="button-secondary" onClick={onExit}>Return to secure access</button>
      </header>
      <div role="note" className="rounded-md border border-amber-500/40 bg-amber-500/10 p-4 text-sm text-amber-200">SIMULATION ONLY: These controls change browser-local synthetic state. No API requests, physical devices, network probes, or operational systems are involved.</div>
      <section aria-label="Simulated devices" className="grid gap-4 md:grid-cols-3">
        {devices.map((device) => <article key={device.id} className="panel space-y-4 p-5">
          <div><p className="font-mono text-xs text-slate-400">{device.id}</p><h2 className="mt-1 font-semibold">{device.label}</h2></div>
          <p role="status" className={device.running ? 'text-emerald-300' : 'text-slate-400'}>{device.running ? 'Running (simulated)' : 'Stopped (simulated)'}</p>
          <button type="button" className="button-primary w-full" onClick={() => toggle(device.id)} aria-label={`${device.running ? 'Stop' : 'Start'} simulated ${device.label}`}>{device.running ? 'Simulate stop' : 'Simulate start'}</button>
        </article>)}
      </section>
      <div className="flex justify-end"><button type="button" className="button-secondary" onClick={reset}>Reset simulation</button></div>
      <section className="panel p-5"><h2 className="font-semibold">Local simulation event log</h2><ul aria-label="Simulation events" className="mt-3 space-y-2 font-mono text-sm text-slate-400">{events.map((event, index) => <li key={`${index}-${event}`}>{event}</li>)}</ul></section>
    </div>
  </main>
}
