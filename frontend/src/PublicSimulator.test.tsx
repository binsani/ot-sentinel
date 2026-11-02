import { renderToStaticMarkup } from 'react-dom/server'
import { describe, expect, it } from 'vitest'
import { PublicSimulator, toggleSimulatedDevice } from './PublicSimulator'

describe('public synthetic simulator', () => {
  it('renders no-login simulated controls without making API requests', () => {
    const markup = renderToStaticMarkup(<PublicSimulator onExit={() => undefined} />)
    expect(markup).toContain('no login required')
    expect(markup).toContain('Simulate stop')
    expect(markup).toContain('Simulate start')
    expect(markup).toContain('Return to secure access')
    expect(markup).toContain('No API requests')
  })

  it('toggles only the requested synthetic device without mutating input', () => {
    const initial = [
      { id: 'P-101', label: 'Pump', running: true },
      { id: 'P-102', label: 'Backup', running: false },
    ]
    const next = toggleSimulatedDevice(initial, 'P-101')
    expect(next[0].running).toBe(false)
    expect(next[1].running).toBe(false)
    expect(initial[0].running).toBe(true)
    expect(toggleSimulatedDevice(next, 'P-101')[0].running).toBe(true)
  })
})
