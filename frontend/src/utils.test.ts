import { describe, expect, it } from 'vitest'
import { ago, bytes } from './utils'

describe('bytes', () => {
  it('formats KiB, MiB, and GiB values', () => {
    expect(bytes(1024)).toBe('1 KB')
    expect(bytes(1024 ** 2)).toBe('1 MB')
    expect(bytes(1.5 * 1024 ** 3)).toBe('1.5 GB')
  })
})

describe('ago', () => {
  it('formats elapsed time and clamps future timestamps', () => {
    const now = Date.parse('2026-01-01T00:00:00Z')
    expect(ago('2025-12-31T23:59:30Z', now)).toBe('30s ago')
    expect(ago('2025-12-31T23:00:00Z', now)).toBe('1h ago')
    expect(ago('2026-01-01T00:01:00Z', now)).toBe('0s ago')
  })
})
