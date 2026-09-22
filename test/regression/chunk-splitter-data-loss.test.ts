import { readFile } from 'node:fs/promises'
import { describe, expect, it } from 'vitest'
import { ChunkBuilder, ChunkSplitter, type ChunkEntry } from '../../src/chunk/splitter.js'
import { fixture, FIXTURES } from '../fixtures/generate.js'

// Regression: https://github.com/ethersphere/core-sdk/issues/7
async function split(name: keyof typeof FIXTURES, encrypted: boolean) {
  const data = new Uint8Array(await readFile(await fixture(name)))
  const emitted = new Set<ChunkBuilder>()
  const intermediate = new Set<ChunkBuilder>()

  const splitter = new ChunkSplitter(
    async (batch: ChunkEntry[]) => {
      for (const { chunk } of batch) {
        emitted.add(chunk)
      }

      return []
    },
    undefined,
    encrypted,
    chunk => intermediate.add(chunk),
  )

  await splitter.append(data)
  const root = await splitter.finalize()
  intermediate.add(root)

  return {
    root,
    expectedDataChunks: Math.ceil(data.length / 4096),
    emittedDataChunks: [...emitted].filter(chunk => !intermediate.has(chunk)).length,
    size: data.length,
  }
}

describe('ChunkSplitter emits every data chunk', () => {
  it('for a file just past 64 MiB (unencrypted)', async () => {
    const { root, expectedDataChunks, emittedDataChunks, size } = await split('splitter-data-loss-67600000.bin', false)

    expect(emittedDataChunks).toBe(expectedDataChunks)
    expect(root.span).toBe(BigInt(size))
    expect(root.hash().toHex()).toBe('942ef495c81b64c2d32ca75e0b03b67072e283e08e9651aef015d594b588af49')
  }, 120_000)

  it('for a file just past 16 MiB (encrypted)', async () => {
    const { root, expectedDataChunks, emittedDataChunks, size } = await split(
      'splitter-data-loss-encrypted-16850000.bin',
      true,
    )

    expect(emittedDataChunks).toBe(expectedDataChunks)
    expect(root.span).toBe(BigInt(size))
  }, 120_000)

  it('for a file small enough to stay single-level', async () => {
    const { expectedDataChunks, emittedDataChunks } = await split('small.bin', false)

    expect(emittedDataChunks).toBe(expectedDataChunks)
  }, 120_000)
})
