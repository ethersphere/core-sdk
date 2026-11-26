import { describe, expect, it } from 'vitest'
import { ChunkBuilder, ChunkTreeBuilder } from '../src/chunk/builder.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../src/erasure-coding/batch.js'
import { getParities } from '../src/erasure-coding/levels.js'

describe('makeErasureBatch + makeIntermediateChunkHandler', () => {
  it('produces RS parity chunks for a multi-chunk unencrypted upload and flags the intermediate chunk', async () => {
    const uploaded: ChunkBuilder[] = []
    const onChunk = async (chunk: ChunkBuilder) => {
      uploaded.push(chunk)
    }
    const level = 1 // MEDIUM

    const splitter = new ChunkTreeBuilder(
      makeErasureBatch(level, false, onChunk),
      undefined,
      false,
      makeIntermediateChunkHandler(level),
    )

    // Exactly 2 full 4096-byte leaf chunks, no partial trailing chunk.
    const payload = new Uint8Array(4096 * 2).fill(7)
    await splitter.append(payload)
    const root = await splitter.finalize()

    const dataChunks = 2
    const parityChunks = getParities(level, dataChunks, false)
    expect(parityChunks).toBeGreaterThan(0)
    expect(uploaded).toHaveLength(dataChunks + parityChunks)

    // root wraps the 2 leaf chunks; its span (with the redundancy flag byte
    // masked off) is the sum of their spans.
    expect(root.span & 0x00ffffffffffffffn).toBe(BigInt(payload.length))

    // redundancy level flag: bit 7 of span byte 7 set to level | 0x80,
    // matching Bee's redundancy.EncodeLevel.
    const spanByte7 = Number((root.span >> 56n) & 0xffn)
    expect(spanByte7).toBe(level | 0x80)
  })

  it('produces no parity chunks and no redundancy flag for redundancy level NONE (0)', async () => {
    const uploaded: ChunkBuilder[] = []
    const onChunk = async (chunk: ChunkBuilder) => {
      uploaded.push(chunk)
    }

    const splitter = new ChunkTreeBuilder(makeErasureBatch(0, false, onChunk), undefined, false, makeIntermediateChunkHandler(0))
    const payload = new Uint8Array(4096 * 2).fill(7)
    await splitter.append(payload)
    const root = await splitter.finalize()

    expect(uploaded).toHaveLength(2)
    const spanByte7 = Number((root.span >> 56n) & 0xffn)
    expect(spanByte7).toBe(0)
  })

  it('produces encrypted RS parity chunks wrapping the encrypted span+payload', async () => {
    const uploaded: Array<{ chunk: ChunkBuilder; key?: Uint8Array }> = []
    const onChunk = async (chunk: ChunkBuilder, key?: Uint8Array) => {
      uploaded.push({ chunk, key })
    }
    const level = 1

    const splitter = new ChunkTreeBuilder(makeErasureBatch(level, true, onChunk), undefined, true)
    const payload = new Uint8Array(4096 * 2).fill(9)
    await splitter.append(payload)
    await splitter.finalize()

    const dataChunks = 2
    const parityChunks = getParities(level, dataChunks, true)
    expect(parityChunks).toBeGreaterThan(0)
    expect(uploaded).toHaveLength(dataChunks + parityChunks)

    // the 2 data chunks were uploaded with an encryption key, the parity chunks weren't
    expect(uploaded.slice(0, dataChunks).every(({ key }) => key !== undefined)).toBe(true)
    expect(uploaded.slice(dataChunks).every(({ key }) => key === undefined)).toBe(true)
  })
})
