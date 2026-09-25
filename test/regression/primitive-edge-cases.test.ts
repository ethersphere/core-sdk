import { describe, expect, it } from 'vitest'
import { BatchId } from '../../src/bytes/batch-id.js'
import { Bytes } from '../../src/bytes/bytes.js'
import {
  base32ToUint8Array,
  hexToUint8Array,
  indexOf,
  numberToUint256,
  uint8ArrayToBase32,
  uint8ArrayToBase64,
} from '../../src/bytes/encoding.js'
import { PrivateKey } from '../../src/bytes/private-key.js'
import { Reference } from '../../src/bytes/reference.js'
import { xorCypher } from '../../src/encryption/xor-cipher.js'
import { rsEncode } from '../../src/erasure-coding/reed-solomon.js'
import { Stamper } from '../../src/stamper/stamper.js'

const ENCODER = new TextEncoder()

describe('Bytes does not alias its input', () => {
  it('ignores later writes to the Uint8Array it was built from', () => {
    const raw = new Uint8Array(32).fill(1)
    const reference = new Reference(raw)
    const batchId = new BatchId(raw)
    raw[0] = 9

    expect(reference.toUint8Array()[0]).toBe(1)
    expect(batchId.toUint8Array()[0]).toBe(1)
  })

  it('ignores later writes to the ArrayBuffer it was built from', () => {
    const buffer = new Uint8Array(4).fill(1).buffer
    const bytes = new Bytes(buffer)
    new Uint8Array(buffer)[0] = 9

    expect(bytes.toUint8Array()).toEqual(new Uint8Array(4).fill(1))
  })

  it('copies only the viewed range of a subarray', () => {
    const backing = Uint8Array.from([0, 1, 2, 3, 4, 5])
    const bytes = new Bytes(backing.subarray(2, 4))
    backing[2] = 9

    expect(bytes.length).toBe(2)
    expect(bytes.toUint8Array()).toEqual(Uint8Array.from([2, 3]))
  })

  it('still checks the length of a copied input', () => {
    expect(() => new Reference(new Uint8Array(31))).toThrow(/length/)
  })

  it('is unaffected by writes to the array returned by toUint8Array', () => {
    const bytes = new Bytes(new Uint8Array(4).fill(1))
    bytes.toUint8Array()[0] = 9

    expect(bytes.toUint8Array()[0]).toBe(1)
  })
})

describe('base32 padding', () => {
  const rfc4648: [string, string][] = [
    ['', ''],
    ['f', 'MY======'],
    ['fo', 'MZXQ===='],
    ['foo', 'MZXW6==='],
    ['foob', 'MZXW6YQ='],
    ['fooba', 'MZXW6YTB'],
    ['foobar', 'MZXW6YTBOI======'],
  ]

  it.each(rfc4648)('encodes %j as the RFC 4648 vector %j', (input, expected) => {
    expect(uint8ArrayToBase32(ENCODER.encode(input))).toBe(expected)
  })

  it.each(rfc4648)('decodes the RFC 4648 vector for %j', (input, encoded) => {
    expect(base32ToUint8Array(encoded)).toEqual(ENCODER.encode(input))
  })

  it('always produces a multiple of 8 characters and round-trips', () => {
    for (let length = 0; length <= 16; length++) {
      const bytes = Uint8Array.from({ length }, (_, i) => (i * 37 + 11) & 0xff)
      const encoded = uint8ArrayToBase32(bytes)

      expect(encoded.length % 8).toBe(0)
      expect(base32ToUint8Array(encoded)).toEqual(bytes)
    }
  })

  it('keeps base64 padding at a multiple of 4', () => {
    expect(uint8ArrayToBase64(ENCODER.encode('f'))).toBe('Zg==')
    expect(uint8ArrayToBase64(ENCODER.encode('fo'))).toBe('Zm8=')
    expect(uint8ArrayToBase64(ENCODER.encode('foo'))).toBe('Zm9v')
    expect(uint8ArrayToBase64(ENCODER.encode('foobar'))).toBe('Zm9vYmFy')
  })
})

describe('hexToUint8Array validation', () => {
  it.each(['zz', 'g0', '0x0g', 'abc', '0xabc', ' 00', '00 ', '0x0x00', '-1'])('rejects %j', hex => {
    expect(() => hexToUint8Array(hex)).toThrow(/invalid hex/)
  })

  it.each([
    ['', []],
    ['0x', []],
    ['0X', []],
    ['00ff', [0x00, 0xff]],
    ['0xABcd', [0xab, 0xcd]],
    ['0XABCD', [0xab, 0xcd]],
  ])('accepts %j', (hex, expected) => {
    expect(hexToUint8Array(hex)).toEqual(Uint8Array.from(expected))
  })
})

describe('rsEncode without data shards', () => {
  it.each([0, 1, 4])('throws a clear error with %i parity shards', parityCount => {
    expect(() => rsEncode([], parityCount)).toThrow(/at least one data shard/)
  })
})

describe('xorCypher with an empty key', () => {
  it('throws instead of returning the input unchanged', () => {
    expect(() => xorCypher(Uint8Array.from([1, 2]), new Uint8Array())).toThrow(/key must not be empty/)
  })

  it('throws even for empty input', () => {
    expect(() => xorCypher(new Uint8Array(), new Uint8Array())).toThrow(/key must not be empty/)
  })

  it('still repeats a one-byte key', () => {
    expect(xorCypher(Uint8Array.from([1, 2, 3]), Uint8Array.from([0xff]))).toEqual(Uint8Array.from([0xfe, 0xfd, 0xfc]))
  })
})

describe('Stamper depth validation', () => {
  const privateKey = new PrivateKey(numberToUint256(999n, 'BE'))
  const batchId = new Uint8Array(32).fill(1)

  it.each([16, 15, 0, -1, 16.5, 17.5, NaN, Infinity])('fromBlank rejects depth %d', depth => {
    expect(() => Stamper.fromBlank(privateKey, batchId, depth)).toThrow(/depth/)
  })

  it.each([16, 16.5, NaN])('fromState rejects depth %d', depth => {
    expect(() => Stamper.fromState(privateKey, batchId, new Uint32Array(65536), depth)).toThrow(/depth/)
  })

  it('accepts the minimum depth of 17 with two slots per bucket', () => {
    expect(Stamper.fromBlank(privateKey, batchId, 17).maxSlot).toBe(2)
  })
})

describe('indexOf with an empty needle', () => {
  const haystack = Uint8Array.from([1, 2, 3])
  const empty = new Uint8Array()

  it('matches at the start', () => {
    expect(indexOf(haystack, empty)).toBe(0)
    expect(indexOf(haystack, empty, 2)).toBe(2)
  })

  it('matches at the end, clamping a start past it', () => {
    expect(indexOf(haystack, empty, 3)).toBe(3)
    expect(indexOf(haystack, empty, 10)).toBe(3)
  })

  it('matches inside an empty haystack', () => {
    expect(indexOf(empty, empty)).toBe(0)
  })

  it('still reports no match for a needle running past the end', () => {
    expect(indexOf(haystack, Uint8Array.from([3, 4]))).toBe(-1)
    expect(indexOf(haystack, Uint8Array.from([1, 2, 3, 4]))).toBe(-1)
    expect(indexOf(haystack, Uint8Array.from([2, 3]))).toBe(1)
  })
})
