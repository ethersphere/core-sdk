import { numberToUint64, uint64ToNumber } from '../bytes/encoding.js'
import { ChunkBuilder, ChunkEntry } from '../chunk/splitter.js'
import { encryptData, encryptSpan } from '../encryption/stream-cipher.js'
import { getParities } from './levels.js'
import { rsEncode } from './reed-solomon.js'
import { encodeRedundancyLevel } from './span.js'
import { Bytes } from '../bytes/bytes.js'

// Constructs a ChunkBuilder from a 4104-byte raw shard (8-byte LE span + 4096-byte data).
function chunkFromBytes(bytes: Uint8Array): ChunkBuilder {
  const chunk = new ChunkBuilder(uint64ToNumber(bytes.subarray(0, 8), 'LE'))
  chunk.writer.buffer.set(bytes.subarray(8, 4104))

  return chunk
}

/**
 * Returns an onIntermediateChunk callback for ChunkSplitter that encodes the
 * redundancy level into bit 7 of span byte 7 whenever the intermediate chunk
 * contains parity refs. Matches Bee's redundancy.EncodeLevel: span[7] = level | 0x80.
 * This allows Bee's joiner to locate parity refs and perform RS reconstruction.
 */
export function makeIntermediateChunkHandler(level: number): (chunk: ChunkBuilder, hasParity: boolean) => void {
  return (chunk, hasParity) => {
    if (hasParity && level > 0) {
      chunk.span = encodeRedundancyLevel(chunk.span, level)
    }
  }
}

/**
 * Returns an onBatch callback for ChunkSplitter that:
 *  1. Uploads all data chunks in the batch via onChunk
 *  2. Computes RS parity shards from the data chunk bytes
 *  3. Uploads parity chunks via onChunk
 *  4. Returns the parity ChunkEntry[] for the splitter to include in the parent tree node
 */
export function makeErasureBatch(
  level: number,
  encrypted: boolean,
  onChunk: (chunk: ChunkBuilder, key?: Uint8Array) => Promise<void>,
): (batch: ChunkEntry[]) => Promise<ChunkEntry[]> {
  return async (batch: ChunkEntry[]): Promise<ChunkEntry[]> => {
    for (const { chunk, key } of batch) {
      await onChunk(chunk, key)
    }
    if (level <= 0) return []

    if (encrypted) {
      const parityCount = getParities(level, batch.length, true)
      if (parityCount === 0) return []

      const shardBytes = batch.map(({ chunk, key }) =>
        Bytes.concat(encryptSpan(key!, numberToUint64(chunk.span, 'LE')), encryptData(key!, chunk.writer.buffer)),
      )
      const parityShards = rsEncode(shardBytes, parityCount)
      const parityEntries: ChunkEntry[] = []
      for (const bytes of parityShards) {
        const parityChunk = chunkFromBytes(bytes)
        await onChunk(parityChunk)
        parityEntries.push({ chunk: parityChunk })
      }

      return parityEntries
    }

    const parityCount = getParities(level, batch.length, false)
    if (parityCount === 0) return []

    const dataBytes = batch.map(({ chunk }) => chunk.build())
    const parityShards = rsEncode(dataBytes, parityCount)
    const parityEntries: ChunkEntry[] = []
    for (const bytes of parityShards) {
      const chunk = chunkFromBytes(bytes)
      await onChunk(chunk)
      parityEntries.push({ chunk })
    }

    return parityEntries
  }
}
