import { describe, expect, it } from 'vitest'
import { Bytes } from '../src/bytes/bytes.js'
import { numberToUint64 } from '../src/bytes/encoding.js'
import { Reference } from '../src/bytes/reference.js'
import { ChunkJoiner } from '../src/chunk/joiner.js'
import { ChunkBuilder, ChunkSplitter } from '../src/chunk/splitter.js'
import { encryptData, encryptSpan } from '../src/encryption/stream-cipher.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../src/erasure-coding/batch.js'
import { getMaxShards } from '../src/erasure-coding/levels.js'

function payload(size: number): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => (i * 5 + (i >> 12) * 11 + 1) % 256)
}

function serialize(chunk: ChunkBuilder, key?: Uint8Array): Uint8Array {
  if (!key) return chunk.build()

  return Bytes.concat(encryptSpan(key, numberToUint64(chunk.span, 'LE')), encryptData(key, chunk.writer.buffer))
}

function makeStore() {
  const chunks = new Map<string, Uint8Array>()
  const requested: unknown[] = []

  async function put(chunk: ChunkBuilder, key?: Uint8Array, address?: Reference): Promise<void> {
    chunks.set((address ?? chunk.hash()).toHex(), serialize(chunk, key))
  }

  async function split(data: Uint8Array, { encrypted = false, level = 0 } = {}): Promise<Reference> {
    const splitter = new ChunkSplitter(
      makeErasureBatch(level, encrypted, put),
      getMaxShards(level, encrypted),
      encrypted,
      makeIntermediateChunkHandler(level),
    )
    await splitter.append(data)
    const root = await splitter.finalize()

    if (!encrypted) {
      await put(root)

      return root.hash()
    }
    const { address, key } = root.encryptedHash()
    await put(root, key, address)

    return new Reference(Bytes.concat(address.toUint8Array(), key))
  }

  async function fetch(address: Reference): Promise<Uint8Array> {
    requested.push(address)
    const data = chunks.get(address.toHex())
    if (!data) throw new Error(`not found: ${address.toHex()}`)

    return data
  }

  return { chunks, requested, split, fetch }
}

describe('ChunkJoiner.collect with a Reference', () => {
  const data = payload(4096 * 20 + 33)

  it('reconstructs an unencrypted payload from a Reference', async () => {
    const store = makeStore()
    const reference = await store.split(data)

    expect(await ChunkJoiner.collect(reference, store.fetch)).toEqual(data)
  })

  it('decrypts the payload behind a 64-byte reference', async () => {
    const store = makeStore()
    const reference = await store.split(data, { encrypted: true })

    expect(await ChunkJoiner.collect(reference, store.fetch)).toEqual(data)
  })

  it('reconstructs an erasure-coded encrypted payload', async () => {
    const store = makeStore()
    const reference = await store.split(data, { encrypted: true, level: 3 })

    expect(await ChunkJoiner.collect(reference, store.fetch)).toEqual(data)
  })

  it.each([false, true])('accepts a hex string reference (encrypted: %s)', async encrypted => {
    const store = makeStore()
    const reference = await store.split(data, { encrypted })

    expect(await ChunkJoiner.collect(reference.toHex(), store.fetch)).toEqual(data)
  })

  it('accepts a CID string reference', async () => {
    const store = makeStore()
    const reference = await store.split(data)

    expect(await ChunkJoiner.collect(reference.toCid('manifest'), store.fetch)).toEqual(data)
  })

  it('fetches every chunk by its 32-byte Reference, without the decryption key', async () => {
    const store = makeStore()
    const reference = await store.split(data, { encrypted: true })

    await ChunkJoiner.collect(reference, store.fetch)

    expect(store.requested.length).toBeGreaterThan(1)
    for (const address of store.requested) {
      expect(address).toBeInstanceOf(Reference)
      expect((address as Reference).length).toBe(32)
    }
  })

  it('still passes raw Uint8Array addresses when given a Uint8Array', async () => {
    const store = makeStore()
    const reference = await store.split(data)
    const requested: unknown[] = []

    const collected = await ChunkJoiner.collect(reference.toUint8Array(), async address => {
      requested.push(address)

      return store.fetch(new Reference(address))
    })

    expect(collected).toEqual(data)
    expect(requested.every(address => address instanceof Uint8Array)).toBe(true)
  })

  it.each([false, true])('verifies chunks fetched through a Reference (encrypted: %s)', async encrypted => {
    const store = makeStore()
    const reference = await store.split(data, { encrypted })

    expect(await ChunkJoiner.collect(reference, store.fetch, { verify: true })).toEqual(data)
  })

  it.each([false, true])('rejects a tampered chunk fetched through a Reference (encrypted: %s)', async encrypted => {
    const store = makeStore()
    const reference = await store.split(data, { encrypted })
    const [address, chunk] = [...store.chunks].find(([hex]) => hex !== reference.toHex().slice(0, 64))!
    const tampered = chunk.slice()
    tampered[tampered.length - 1]! ^= 1
    store.chunks.set(address, tampered)

    await expect(ChunkJoiner.collect(reference, store.fetch, { verify: true })).rejects.toThrow(
      `Chunk integrity check failed: ${address}`,
    )
  })

  it('rejects a string that is not a valid reference', async () => {
    await expect(ChunkJoiner.collect('abcd', async () => new Uint8Array(0))).rejects.toThrow()
  })
})
