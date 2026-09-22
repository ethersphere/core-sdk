import { inspect } from 'node:util'
import { describe, expect, it } from 'vitest'
import { keccak256 } from '../src/crypto/keccak.js'
import { BatchId } from '../src/bytes/batch-id.js'
import { Bytes } from '../src/bytes/bytes.js'
import { EthAddress } from '../src/bytes/eth-address.js'
import { FeedIndex } from '../src/bytes/feed-index.js'
import { Identifier } from '../src/bytes/identifier.js'
import { PeerAddress } from '../src/bytes/peer-address.js'
import { Span } from '../src/bytes/span.js'
import { Topic } from '../src/bytes/topic.js'
import { TransactionId } from '../src/bytes/transaction-id.js'

describe('Bytes', () => {
  it('constructs from a Uint8Array, hex string, ArrayBuffer, and another Bytes', () => {
    const fromArray = new Bytes(Uint8Array.from([1, 2, 3]))
    const fromHex = new Bytes('010203')
    const fromPrefixedHex = new Bytes('0x010203')
    const fromArrayBuffer = new Bytes(Uint8Array.from([1, 2, 3]).buffer)
    const fromBytes = new Bytes(fromArray)

    for (const b of [fromArray, fromHex, fromPrefixedHex, fromArrayBuffer, fromBytes]) {
      expect(b.toHex()).toBe('010203')
    }
  })

  it('rejects a falsy constructor argument', () => {
    expect(() => new Bytes('' as unknown as Uint8Array)).toThrow()
  })

  it('rejects an invalid hex string', () => {
    expect(() => new Bytes('not-hex')).toThrow()
    expect(() => new Bytes('0x0')).toThrow() // odd length
  })

  it('accepts an uppercase 0X prefix and uppercase hex digits', () => {
    expect(new Bytes('0X010203').toHex()).toBe('010203')
    expect(new Bytes('0XABCDEF').toHex()).toBe('abcdef')
    expect(new Bytes('ABCDEF').toHex()).toBe('abcdef')
  })

  it('validates a single expected byte length', () => {
    expect(() => new Bytes(Uint8Array.from([1, 2]), 3)).toThrow()
    expect(new Bytes(Uint8Array.from([1, 2, 3]), 3).length).toBe(3)
  })

  it('validates a set of allowed byte lengths', () => {
    expect(new Bytes(new Uint8Array(32), [32, 64]).length).toBe(32)
    expect(new Bytes(new Uint8Array(64), [32, 64]).length).toBe(64)
    expect(() => new Bytes(new Uint8Array(10), [32, 64])).toThrow()
  })

  it('round-trips through hex, base64, and base32', () => {
    const bytes = new Bytes(Uint8Array.from({ length: 20 }, (_, i) => i * 5))
    expect(new Bytes(bytes.toHex())).toEqual(bytes)
    expect(bytes.toBase64().length).toBeGreaterThan(0)
    expect(bytes.toBase32().length).toBeGreaterThan(0)
  })

  it('encodes/decodes UTF-8 (including multi-byte characters)', () => {
    const bytes = Bytes.fromUtf8('hello 世界')
    expect(bytes.toUtf8()).toBe('hello 世界')
  })

  it('parses JSON from its UTF-8 content', () => {
    const bytes = Bytes.fromUtf8(JSON.stringify({ a: 1 }))
    expect(bytes.parseJson()).toEqual({ a: 1 })
  })

  it('stringifies to hex, standalone and as a property', () => {
    const id = new BatchId('ab'.repeat(32))
    expect(id.toJSON()).toBe('ab'.repeat(32))
    expect(JSON.stringify(id)).toBe(`"${'ab'.repeat(32)}"`)
    expect(JSON.stringify({ id })).toBe(`{"id":"${'ab'.repeat(32)}"}`)
    expect(`${id}`).toBe('ab'.repeat(32))
  })

  it('inspects as hex, standalone and nested', () => {
    const id = new BatchId('ab'.repeat(32))
    expect(inspect(id)).toBe('ab'.repeat(32))
    expect(inspect({ id }, { breakLength: Infinity })).toBe(`{ id: ${'ab'.repeat(32)} }`)
    expect(inspect([new Span('0102030405060708')])).toBe('[ 0102030405060708 ]')
  })

  it('static keccak256 matches the direct function', () => {
    const input = Uint8Array.from([1, 2, 3])
    expect(Bytes.keccak256(input).toUint8Array()).toEqual(keccak256(input))
  })

  it('fromSlice extracts a sub-range', () => {
    const source = Uint8Array.from([1, 2, 3, 4, 5])
    expect(Bytes.fromSlice(source, 1, 2).toHex()).toBe('0203')
    expect(Bytes.fromSlice(source, 2).toHex()).toBe('030405')
  })

  it('equals compares by content, not identity', () => {
    const a = new Bytes(Uint8Array.from([1, 2, 3]))
    const b = new Bytes('010203')
    expect(a.equals(b)).toBe(true)
    expect(a.equals('010204')).toBe(false)
  })
})

describe('EthAddress', () => {
  it('toChecksum matches the canonical EIP-55 vectors', () => {
    const vectors = [
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed',
      '0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359',
      '0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB',
      '0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb',
    ]
    for (const expected of vectors) {
      expect(new EthAddress(expected).toChecksum()).toBe(expected)
    }
  })

  it('rejects the wrong length', () => {
    expect(() => new EthAddress(new Uint8Array(19))).toThrow()
  })
})

describe('Identifier / Topic', () => {
  it('fromString hashes the UTF-8 encoding with keccak256', () => {
    const value = 'my-topic'
    const expected = keccak256(new TextEncoder().encode(value))
    expect(Identifier.fromString(value).toUint8Array()).toEqual(expected)
    expect(Topic.fromString(value).toUint8Array()).toEqual(expected)
  })
})

describe('Span', () => {
  it('round-trips a bigint (little-endian)', () => {
    const span = Span.fromBigInt(4096n)
    expect(span.toBigInt()).toBe(4096n)
    expect(span.length).toBe(8)
  })

  it('fromSlice reads an 8-byte window', () => {
    const buffer = new Uint8Array(16)
    buffer.set(Span.fromBigInt(42n).toUint8Array(), 4)
    expect(Span.fromSlice(buffer, 4).toBigInt()).toBe(42n)
  })
})

describe('FeedIndex', () => {
  it('round-trips a bigint (big-endian)', () => {
    expect(FeedIndex.fromBigInt(7n).toBigInt()).toBe(7n)
  })

  it('next() increments normally', () => {
    expect(FeedIndex.fromBigInt(7n).next().toBigInt()).toBe(8n)
  })

  it('MINUS_ONE.next() wraps to 0', () => {
    expect(FeedIndex.MINUS_ONE.next().toBigInt()).toBe(0n)
  })
})

describe('plain 32-byte wrappers', () => {
  it('TransactionId, PeerAddress, BatchId all enforce 32 bytes', () => {
    expect(new TransactionId(new Uint8Array(32)).length).toBe(32)
    expect(() => new TransactionId(new Uint8Array(31))).toThrow()
    expect(new PeerAddress(new Uint8Array(32)).length).toBe(32)
    expect(() => new PeerAddress(new Uint8Array(31))).toThrow()
    expect(new BatchId(new Uint8Array(32)).length).toBe(32)
    expect(() => new BatchId(new Uint8Array(31))).toThrow()
  })
})
