import { describe, expect, it } from 'vitest'
import { Reference } from '../src/bytes/reference.js'
import { DataSplitter, SplitChunk } from '../src/chunk/data-splitter.js'
import { ChunkJoiner } from '../src/chunk/joiner.js'

function payload(size: number): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => (i * 5 + (i >> 12) * 11 + 1) % 256)
}

function makeStore() {
  const chunks = new Map<string, Uint8Array>()
  const requested: unknown[] = []

  async function onChunk({ address, data }: SplitChunk): Promise<void> {
    chunks.set(address.toHex(), data)
  }

  async function fetch(address: Reference): Promise<Uint8Array> {
    requested.push(address)
    const data = chunks.get(address.toHex())
    if (!data) throw new Error(`not found: ${address.toHex()}`)

    return data
  }

  return { chunks, requested, onChunk, fetch }
}

describe('ChunkJoiner.collect with a Reference', () => {
  const data = payload(4096 * 20 + 33)

  it('reconstructs an unencrypted payload from a Reference', async () => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { onChunk: store.onChunk })

    expect(await ChunkJoiner.collect(reference, store.fetch)).toEqual(data)
  })

  it('decrypts the payload behind a 64-byte reference', async () => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { encrypted: true, onChunk: store.onChunk })

    expect(await ChunkJoiner.collect(reference, store.fetch)).toEqual(data)
  })

  it('reconstructs an erasure-coded encrypted payload', async () => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { encrypted: true, redundancyLevel: 3, onChunk: store.onChunk })

    expect(await ChunkJoiner.collect(reference, store.fetch)).toEqual(data)
  })

  it.each([false, true])('accepts a hex string reference (encrypted: %s)', async encrypted => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { encrypted, onChunk: store.onChunk })

    expect(await ChunkJoiner.collect(reference.toHex(), store.fetch)).toEqual(data)
  })

  it('accepts a CID string reference', async () => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { onChunk: store.onChunk })

    expect(await ChunkJoiner.collect(reference.toCid('manifest'), store.fetch)).toEqual(data)
  })

  it('fetches every chunk by its 32-byte Reference, without the decryption key', async () => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { encrypted: true, onChunk: store.onChunk })

    await ChunkJoiner.collect(reference, store.fetch)

    expect(store.requested.length).toBeGreaterThan(1)
    for (const address of store.requested) {
      expect(address).toBeInstanceOf(Reference)
      expect((address as Reference).length).toBe(32)
    }
  })

  it('still passes raw Uint8Array addresses when given a Uint8Array', async () => {
    const store = makeStore()
    const reference = await DataSplitter.split(data, { onChunk: store.onChunk })
    const requested: unknown[] = []

    const collected = await ChunkJoiner.collect(reference.toUint8Array(), async address => {
      requested.push(address)

      return store.fetch(new Reference(address))
    })

    expect(collected).toEqual(data)
    expect(requested.every(address => address instanceof Uint8Array)).toBe(true)
  })

  it('rejects a string that is not a valid reference', async () => {
    await expect(ChunkJoiner.collect('abcd', async () => new Uint8Array(0))).rejects.toThrow()
  })
})
