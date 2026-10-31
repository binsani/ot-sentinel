import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { PublicSimulator } from './PublicSimulator'

describe('public synthetic simulator', () => {
  it('starts and stops a synthetic device without credentials', () => {
    render(<PublicSimulator onExit={() => undefined} />)
    expect(screen.getByText('Running (simulated)')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Stop simulated Cooling circulation pump' }))
    expect(screen.getByText('P-101 simulated stop')).toBeTruthy()
    fireEvent.click(screen.getByRole('button', { name: 'Reset simulation' }))
    expect(screen.getByText('Synthetic simulation reset')).toBeTruthy()
  })

  it('exposes a return to secure access action', () => {
    let exited = false
    render(<PublicSimulator onExit={() => { exited = true }} />)
    fireEvent.click(screen.getByRole('button', { name: 'Return to secure access' }))
    expect(exited).toBe(true)
  })
})
