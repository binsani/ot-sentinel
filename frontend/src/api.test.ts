import { describe, expect, it } from 'vitest'

import { authHeaders } from './api'

describe('authHeaders', () => {
  it('uses bearer authentication for JWT-shaped credentials', () => {
    expect(authHeaders('header.payload.signature')).toEqual({
      Authorization: 'Bearer header.payload.signature',
    })
  })

  it('uses the bootstrap header for opaque API keys', () => {
    expect(authHeaders('opaque-bootstrap-key')).toEqual({
      'X-API-Key': 'opaque-bootstrap-key',
    })
  })
})
