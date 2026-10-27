import { describe, expect, it } from 'vitest'
import { Reference } from '../src/bytes/reference.js'
import { ChunkBuilder, ChunkEntry, ChunkSplitter } from '../src/chunk/splitter.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../src/erasure-coding/batch.js'
import { getMaxShards } from '../src/erasure-coding/levels.js'
import { MantarayNode } from '../src/mantaray/node.js'

type Seen = { chunk: ChunkBuilder; key?: Uint8Array; address?: Reference }

function expectedAddress({ chunk, key }: Seen): string {
  return (key ? chunk.encryptedHash(key).address : chunk.hash()).toHex()
}

async function splitWithErasure(data: Uint8Array, level: number, encrypted: boolean): Promise<Seen[]> {
  const seen: Seen[] = []
  const onChunk = async (chunk: ChunkBuilder, key?: Uint8Array, address?: Reference) => {
    seen.push({ chunk, key, address })
  }
  const splitter = new ChunkSplitter(
    makeErasureBatch(level, encrypted, onChunk),
    getMaxShards(level, encrypted),
    encrypted,
    makeIntermediateChunkHandler(level),
  )
  await splitter.append(data)
  await splitter.finalize()

  return seen
}

describe('chunk addresses passed to consumers', () => {
  it('ChunkSplitter attaches the correct address to every batch entry', async () => {
    const entries: ChunkEntry[] = []
    const splitter = new ChunkSplitter(async batch => {
      entries.push(...batch)

      return []
    })
    await splitter.append(new Uint8Array(4096 * 300).fill(3))
    await splitter.finalize()

    expect(entries.length).toBeGreaterThan(300)
    for (const entry of entries) {
      expect(entry.address?.toHex()).toBe(expectedAddress(entry))
    }
  })

  it.each([false, true])(
    'makeErasureBatch passes correct addresses for data and parity chunks (encrypted: %s)',
    async encrypted => {
      const seen = await splitWithErasure(new Uint8Array(4096 * 200).fill(5), 2, encrypted)

      const parities = seen.filter(s => !s.key)
      expect(parities.length).toBeGreaterThan(0)
      for (const s of seen) {
        expect(s.address?.toHex()).toBe(expectedAddress(s))
      }
    },
  )

  it.each([false, true])('MantarayNode.saveRecursively passes correct addresses (encrypted: %s)', async encrypted => {
    const node = new MantarayNode({ encrypt: encrypted })
    node.addFork('a.txt', new Uint8Array(32).fill(1))
    node.addFork('b/c.txt', new Uint8Array(32).fill(2))

    const seen: Seen[] = []
    await node.saveRecursively(async (chunk, key, address) => {
      seen.push({ chunk, key, address })
    })

    expect(seen.length).toBeGreaterThan(0)
    for (const s of seen) {
      expect(s.address?.toHex()).toBe(expectedAddress(s))
    }
  })
})
