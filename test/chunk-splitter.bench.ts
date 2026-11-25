import { bench } from 'vitest'
import { ChunkSplitter } from '../src/chunk/chunk-splitter.js'

// ~1MB - large enough to exercise multiple levels of the tree, not just a
// single leaf chunk.
const data = new Uint8Array(1024 * 1024).fill(0x42)

bench('ChunkSplitter.root 1MB payload', async () => {
  await ChunkSplitter.root(data)
})

const onChunk = async () => {}

bench('ChunkSplitter.split 1MB payload', async () => {
  await ChunkSplitter.split(data, { onChunk })
})

bench('ChunkSplitter.split 1MB payload at redundancy level 2', async () => {
  await ChunkSplitter.split(data, { redundancyLevel: 2, onChunk })
})

bench('ChunkSplitter.split 1MB encrypted payload', async () => {
  await ChunkSplitter.split(data, { encrypted: true, onChunk })
})
