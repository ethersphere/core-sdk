import { describe, expect, it } from 'vitest'
import { ChunkBuilder, ChunkSplitter, type ChunkEntry } from '../../src/chunk/splitter.js'

// Regression: https://github.com/ethersphere/core-sdk/issues/10
const FILL = 0x33
const MAX_SHARDS = 4
const PARITY = 128 - MAX_SHARDS

interface Split {
  reports: { chunk: ChunkBuilder; hasParity: boolean }[]
  parityAddresses: Set<string>
}

async function split(leaves: number, options: { maxShards?: number; encrypted?: boolean } = {}): Promise<Split> {
  const { maxShards, encrypted = false } = options
  const parityAddresses = new Set<string>()
  const reports: { chunk: ChunkBuilder; hasParity: boolean }[] = []

  const onBatch = async (batch: ChunkEntry[]): Promise<ChunkEntry[]> => {
    if (maxShards === undefined) {
      return []
    }

    return Array.from({ length: PARITY }, (_, index) => {
      const chunk = new ChunkBuilder(4096n)
      chunk.writer.buffer[0] = index
      chunk.writer.buffer[1] = batch.length
      parityAddresses.add(chunk.hash().toHex())

      return { chunk }
    })
  }

  const splitter = new ChunkSplitter(onBatch, maxShards, encrypted, (chunk, hasParity) => {
    reports.push({ chunk, hasParity })
  })
  await splitter.append(new Uint8Array(leaves * 4096).fill(FILL))
  await splitter.finalize()

  return { reports, parityAddresses }
}

function isLeaf(chunk: ChunkBuilder): boolean {
  return chunk.writer.buffer.subarray(0, 32).every(byte => byte === FILL)
}

function carriesParity(chunk: ChunkBuilder, parityAddresses: Set<string>): boolean {
  for (let offset = 0; offset + 32 <= chunk.writer.cursor; offset += 32) {
    if (parityAddresses.has(Buffer.from(chunk.writer.buffer.subarray(offset, offset + 32)).toString('hex'))) {
      return true
    }
  }

  return false
}

describe('ChunkSplitter promotion state', () => {
  const leafCases: [label: string, leaves: number, options: { maxShards?: number; encrypted?: boolean }][] = [
    ['promoted once, with parity', 5, { maxShards: MAX_SHARDS }],
    ['promoted through two levels, with parity', 17, { maxShards: MAX_SHARDS }],
    ['promoted without redundancy', 129, {}],
    ['promoted without redundancy, encrypted', 65, { encrypted: true }],
  ]

  for (const [label, leaves, options] of leafCases) {
    it(`does not report a promoted leaf as an intermediate chunk (${label})`, async () => {
      const { reports } = await split(leaves, options)

      expect(reports.filter(report => isLeaf(report.chunk))).toHaveLength(0)
    })
  }

  it('keeps the parity flag on a promoted intermediate chunk', async () => {
    const { reports, parityAddresses } = await split(18, { maxShards: MAX_SHARDS })
    const withParity = reports.filter(report => carriesParity(report.chunk, parityAddresses))

    expect(withParity.length).toBeGreaterThan(0)
    expect(withParity.filter(report => !report.hasParity)).toHaveLength(0)
  })
})
