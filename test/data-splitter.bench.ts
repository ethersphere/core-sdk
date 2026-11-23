import { bench } from 'vitest'
import { DataSplitter } from '../src/chunk/data-splitter.js'

const data = Uint8Array.from({ length: 1024 * 1024 }, (_, i) => (i * 7 + (i >> 12) * 13 + 3) % 256)
const onChunk = async () => {}

bench('DataSplitter.split 1MB payload', async () => {
  await DataSplitter.split(data, { onChunk })
})

bench('DataSplitter.split 1MB payload at redundancy level 2', async () => {
  await DataSplitter.split(data, { redundancyLevel: 2, onChunk })
})

bench('DataSplitter.split 1MB encrypted payload', async () => {
  await DataSplitter.split(data, { encrypted: true, onChunk })
})
