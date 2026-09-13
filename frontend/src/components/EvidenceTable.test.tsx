import { afterEach, describe, expect, it } from 'vitest'
import { cleanup, render, screen } from '@testing-library/react'
import { EvidenceTable } from './EvidenceTable'

afterEach(cleanup)

describe('EvidenceTable', () => {
  it('renders key labels and primitive values', () => {
    render(<EvidenceTable data={{ connections: 18, jitter_ratio: 0.042, flag: true }} />)
    expect(screen.getByText('connections')).toBeDefined()
    expect(screen.getByText('18')).toBeDefined()
    expect(screen.getByText('jitter_ratio')).toBeDefined()
    expect(screen.getByText('0.042')).toBeDefined()
    expect(screen.getByText('true')).toBeDefined()
  })

  it('renders arrays of primitives as chips', () => {
    render(<EvidenceTable data={{ intervals_s: [30.1, 30.25, 30.2] }} />)
    expect(screen.getByText('30.1')).toBeDefined()
    expect(screen.getByText('30.25')).toBeDefined()
    expect(screen.getByText('30.2')).toBeDefined()
  })

  it('renders nested objects as indented sub-tables', () => {
    render(<EvidenceTable data={{ target: { ip: '185.234.72.19', port: 443 } }} />)
    expect(screen.getByText('ip')).toBeDefined()
    expect(screen.getByText('185.234.72.19')).toBeDefined()
    expect(screen.getByText('port')).toBeDefined()
  })

  it('renders arrays of objects as stacked sub-tables', () => {
    render(
      <EvidenceTable data={{ peers: [{ ip: '10.0.0.2' }, { ip: '10.0.0.3' }] }} />,
    )
    expect(screen.getByText('10.0.0.2')).toBeDefined()
    expect(screen.getByText('10.0.0.3')).toBeDefined()
  })

  it('renders empty data with a placeholder', () => {
    render(<EvidenceTable data={{}} />)
    expect(screen.getByText('No evidence recorded.')).toBeDefined()
  })

  it('renders null values as em-dash', () => {
    render(<EvidenceTable data={{ missing: null }} />)
    expect(screen.getByText('—')).toBeDefined()
  })
})
