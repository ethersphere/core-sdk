import { describe, expect, it } from 'vitest'
import {numberToUint64, uint8ArrayToHex} from '../src/bytes/encoding.js'
import { makeContentAddressedChunk } from '../src/chunk/cac.js'
import { ChunkJoiner } from '../src/chunk/joiner.js'
import { ChunkBuilder, ChunkEntry, ChunkSplitter } from '../src/chunk/splitter.js'
import { encryptData, encryptSpan } from '../src/encryption/stream-cipher.js'
import { getMaxShards, makeErasureBatch, makeIntermediateChunkHandler } from '../src/erasure-coding/index.js'
import { Bytes } from '../src/bytes/bytes.js'

// Captures every sealed chunk (leaf and intermediate) as onBatch sees them,
// so a ChunkJoiner can later fetch them back out by address.
function makeStorage() {
  const store = new Map<string, Uint8Array>()

  async function onBatch(entries: ChunkEntry[]): Promise<ChunkEntry[]> {
    for (const { chunk, key } of entries) {
      if (key) {
        // encryptedHash() only returns {address, key}, not the encrypted
        // bytes themselves - a real storage layer computes those separately,
        // same as here.
        const { address } = chunk.encryptedHash(key)
        const encSpan = encryptSpan(key, numberToUint64(chunk.span, 'LE'))
        const encPayload = encryptData(key, chunk.writer.buffer)
        store.set(uint8ArrayToHex(address.toUint8Array()), Bytes.concat(encSpan, encPayload))
      } else {
        store.set(uint8ArrayToHex(chunk.hash().toUint8Array()), chunk.build())
      }
    }

    return []
  }

  function put(address: Uint8Array, data: Uint8Array) {
    store.set(uint8ArrayToHex(address), data)
  }

  async function fetch(address: Uint8Array): Promise<Uint8Array> {
    const data = store.get(uint8ArrayToHex(address))
    if (!data) throw new Error(`not found: ${uint8ArrayToHex(address)}`)

    return data
  }

  return { onBatch, put, fetch }
}

describe('ChunkSplitter', () => {
  it('a single-chunk payload produces the same address as makeContentAddressedChunk', async () => {
    const data = Uint8Array.from({ length: 100 }, (_, i) => i)
    const root = await ChunkSplitter.root(data)
    const cac = makeContentAddressedChunk(data)

    expect(root.hash().toHex()).toBe(cac.address.toHex())
  })

  it('a full 4096-byte payload also stays a single chunk', async () => {
    const data = new Uint8Array(4096).fill(9)
    const root = await ChunkSplitter.root(data)
    const cac = makeContentAddressedChunk(data)

    expect(root.hash().toHex()).toBe(cac.address.toHex())
  })
})

describe('ChunkSplitter + ChunkJoiner round-trip', () => {
  it('reconstructs a small (single-chunk) payload', async () => {
    const storage = makeStorage()
    const data = Uint8Array.from({ length: 500 }, (_, i) => (i * 3) % 256)

    const splitter = new ChunkSplitter(storage.onBatch)
    await splitter.append(data)
    const root: ChunkBuilder = await splitter.finalize()
    storage.put(root.hash().toUint8Array(), root.build())

    const collected = await ChunkJoiner.collect(root.hash().toUint8Array(), storage.fetch)
    expect(collected).toEqual(data)
  })

  it('reconstructs a multi-chunk payload (spanning several 4096-byte leaves)', async () => {
    const storage = makeStorage()
    const data = Uint8Array.from({ length: 4096 * 5 + 777 }, (_, i) => (i * 7 + 3) % 256)

    const splitter = new ChunkSplitter(storage.onBatch)
    await splitter.append(data)
    const root = await splitter.finalize()
    storage.put(root.hash().toUint8Array(), root.build())

    const collected = await ChunkJoiner.collect(root.hash().toUint8Array(), storage.fetch)
    expect(collected).toEqual(data)
  })

  it('reconstructs an encrypted multi-chunk payload', async () => {
    const storage = makeStorage()
    const data = Uint8Array.from({ length: 4096 * 3 + 123 }, (_, i) => (i * 5 + 1) % 256)

    const splitter = new ChunkSplitter(storage.onBatch, undefined, true)
    await splitter.append(data)
    const root = await splitter.finalize()
    const { address, key } = root.encryptedHash()
    const encSpan = encryptSpan(key, numberToUint64(root.span, 'LE'))
    const encPayload = encryptData(key, root.writer.buffer)
    storage.put(address.toUint8Array(), Bytes.concat(encSpan, encPayload))

    const collected = await ChunkJoiner.collectEncrypted(address.toUint8Array(), key, storage.fetch)
    expect(collected).toEqual(data)
  })

  it('reconstructs an empty payload', async () => {
    const storage = makeStorage()
    const splitter = new ChunkSplitter(storage.onBatch)
    await splitter.append(new Uint8Array(0))
    const root = await splitter.finalize()
    storage.put(root.hash().toUint8Array(), root.build())

    const collected = await ChunkJoiner.collect(root.hash().toUint8Array(), storage.fetch)
    expect(collected).toEqual(new Uint8Array(0))
  })
})

describe('ChunkSplitter + ChunkJoiner round-trip with erasure coding', () => {
  // Regression test: ChunkJoiner used to have no notion of redundancy at all,
  // so it walked every ref in an intermediate node's payload as if it were a
  // data child - including the parity refs makeErasureBatch appends after
  // the real ones - corrupting the reconstructed output with garbage decoded
  // from parity chunk bytes.
  it.each([1, 2, 3, 4])('reconstructs a payload split with redundancy level %i, unencrypted', async level => {
    const storage = makeStorage()
    const onChunk = async (chunk: ChunkBuilder, key?: Uint8Array) => {
      await storage.onBatch([{ chunk, key }])
    }
    const maxShards = getMaxShards(level, false)
    const data = Uint8Array.from({ length: 4096 * (maxShards + 3) + 41 }, (_, i) => (i * 11 + level) % 256)

    const splitter = new ChunkSplitter(
      makeErasureBatch(level, false, onChunk),
      maxShards,
      false,
      makeIntermediateChunkHandler(level),
    )
    await splitter.append(data)
    const root = await splitter.finalize()
    await onChunk(root)

    const collected = await ChunkJoiner.collect(root.hash().toUint8Array(), storage.fetch)
    expect(collected).toEqual(data)
  })

  it('reconstructs an encrypted payload split with redundancy', async () => {
    const storage = makeStorage()
    const level = 2
    const onChunk = async (chunk: ChunkBuilder, key?: Uint8Array) => {
      await storage.onBatch([{ chunk, key }])
    }
    const maxShards = getMaxShards(level, true)
    const data = Uint8Array.from({ length: 4096 * (maxShards + 2) + 17 }, (_, i) => (i * 13) % 256)

    const splitter = new ChunkSplitter(
      makeErasureBatch(level, true, onChunk),
      maxShards,
      true,
      makeIntermediateChunkHandler(level),
    )
    await splitter.append(data)
    const root = await splitter.finalize()
    const { address, key } = root.encryptedHash()
    const encSpan = encryptSpan(key, numberToUint64(root.span, 'LE'))
    const encPayload = encryptData(key, root.writer.buffer)
    storage.put(address.toUint8Array(), Bytes.concat(encSpan, encPayload))

    const collected = await ChunkJoiner.collectEncrypted(address.toUint8Array(), key, storage.fetch)
    expect(collected).toEqual(data)
  })

  it('a small (single-chunk, no parity) redundant payload still reconstructs correctly', async () => {
    const storage = makeStorage()
    const level = 1
    const onChunk = async (chunk: ChunkBuilder, key?: Uint8Array) => {
      await storage.onBatch([{ chunk, key }])
    }
    const data = Uint8Array.from({ length: 500 }, (_, i) => i)

    const splitter = new ChunkSplitter(
      makeErasureBatch(level, false, onChunk),
      getMaxShards(level, false),
      false,
      makeIntermediateChunkHandler(level),
    )
    await splitter.append(data)
    const root = await splitter.finalize()
    await onChunk(root)

    const collected = await ChunkJoiner.collect(root.hash().toUint8Array(), storage.fetch)
    expect(collected).toEqual(data)
  })
})
