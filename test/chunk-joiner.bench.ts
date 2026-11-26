import { bench } from 'vitest'
import { uint8ArrayToHex } from '../src/bytes/encoding.js'
import { ChunkJoiner } from '../src/chunk/joiner.js'
import { ChunkEntry, ChunkTreeBuilder } from '../src/chunk/builder.js'

const store = new Map<string, Uint8Array>()

async function onBatch(entries: ChunkEntry[]): Promise<ChunkEntry[]> {
  for (const { chunk } of entries) {
    store.set(uint8ArrayToHex(chunk.hash().toUint8Array()), chunk.build())
  }

  return []
}

async function fetch(address: Uint8Array): Promise<Uint8Array> {
  return store.get(uint8ArrayToHex(address))!
}

const splitter = new ChunkTreeBuilder(onBatch)
await splitter.append(Uint8Array.from({ length: 1024 * 1024 }, (_, i) => i % 251))
const rootChunk = await splitter.finalize()
const root = rootChunk.hash().toUint8Array()
store.set(uint8ArrayToHex(root), rootChunk.build())

bench('ChunkJoiner.collect 1MB payload', async () => {
  await ChunkJoiner.collect(root, fetch)
})

bench('ChunkJoiner.collect 1MB payload with verify', async () => {
  await ChunkJoiner.collect(root, fetch, { verify: true })
})
