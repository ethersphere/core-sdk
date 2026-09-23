import { describe, expect, it } from 'vitest'
import { Bytes } from '../../src/bytes/bytes.js'
import { numberToUint64, uint8ArrayToHex } from '../../src/bytes/encoding.js'
import { ChunkJoiner } from '../../src/chunk/joiner.js'
import { ChunkBuilder, ChunkSplitter } from '../../src/chunk/splitter.js'
import { encryptData, encryptSpan } from '../../src/encryption/stream-cipher.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../../src/erasure-coding/batch.js'
import { getMaxShards } from '../../src/erasure-coding/levels.js'

// Regression: https://github.com/ethersphere/core-sdk/issues/9
function payload(leaves: number): Uint8Array {
  const data = new Uint8Array(leaves * 4096)
  for (let i = 0; i < data.length; i++) {
    data[i] = (i * 31 + leaves) & 0xff
  }

  return data
}

function serialize(chunk: ChunkBuilder, key?: Uint8Array): Uint8Array {
  if (!key) {
    return chunk.build()
  }

  return Bytes.concat(encryptSpan(key, numberToUint64(chunk.span, 'LE')), encryptData(key, chunk.writer.buffer))
}

async function roundTrip(leaves: number, level: number, encrypted: boolean): Promise<Uint8Array> {
  const data = payload(leaves)
  const store = new Map<string, Uint8Array>()
  const put = async (chunk: ChunkBuilder, key?: Uint8Array) => {
    const address = key ? chunk.encryptedHash(key).address : chunk.hash()
    store.set(address.toHex(), serialize(chunk, key))
  }

  const splitter = new ChunkSplitter(
    makeErasureBatch(level, encrypted, put),
    getMaxShards(level, encrypted),
    encrypted,
    makeIntermediateChunkHandler(level),
  )
  await splitter.append(data)
  const root = await splitter.finalize()
  const rootKey = encrypted ? root.encryptedHash().key : undefined
  await put(root, rootKey)

  const fetch = async (address: Uint8Array) => {
    const chunk = store.get(uint8ArrayToHex(address))
    if (!chunk) {
      throw new Error(`missing chunk ${uint8ArrayToHex(address)}`)
    }

    return chunk
  }

  const rootAddress = rootKey ? root.encryptedHash(rootKey).address.toUint8Array() : root.hash().toUint8Array()

  return rootKey ? ChunkJoiner.collectEncrypted(rootAddress, rootKey, fetch) : ChunkJoiner.collect(rootAddress, fetch)
}

describe('ChunkSplitter only-child promotion', () => {
  const cases: [level: number, encrypted: boolean, leaves: number][] = [
    [1, false, getMaxShards(1, false) + 1],
    [1, false, 129],
    [2, false, getMaxShards(2, false) + 1],
    [1, true, getMaxShards(1, true) + 1],
    [1, true, 65],
    [0, false, 129],
  ]

  for (const [level, encrypted, leaves] of cases) {
    it(`round-trips ${leaves} leaves at level ${level}${encrypted ? ' encrypted' : ''}`, async () => {
      expect(await roundTrip(leaves, level, encrypted)).toEqual(payload(leaves))
    }, 60_000)
  }
})
