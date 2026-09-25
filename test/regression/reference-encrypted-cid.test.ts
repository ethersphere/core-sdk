import { describe, expect, it } from 'vitest'
import { Reference } from '../../src/bytes/reference.js'

const address = '11'.repeat(32)
const encrypted = new Reference(address + '22'.repeat(32))

describe('CID of an encrypted (64-byte) reference', () => {
  it.each(['manifest', 'feed'] as const)('refuses to encode it as a %s CID', type => {
    expect(() => encrypted.toCid(type)).toThrow(/32-byte/)
  })

  it('never yields a CID that decodes to the decryption key', () => {
    let decoded: string | undefined
    try {
      decoded = new Reference(encrypted.toCid('manifest')).toHex()
    } catch {
      decoded = undefined
    }

    expect(decoded).not.toBe('22'.repeat(32))
  })

  it('still round-trips a 32-byte reference', () => {
    const reference = new Reference(address)

    expect(new Reference(reference.toCid('manifest')).toHex()).toBe(address)
    expect(new Reference(reference.toCid('feed')).toHex()).toBe(address)
  })
})
