import { describe, expect, it } from 'vitest'
import { Bytes } from '../../src/bytes/bytes.js'
import { numberToUint64, uint8ArrayToHex } from '../../src/bytes/encoding.js'
import { calculateChunkAddress } from '../../src/chunk/bmt.js'
import { ChunkJoiner } from '../../src/chunk/joiner.js'
import { ChunkBuilder, ChunkEntry, ChunkSplitter } from '../../src/chunk/splitter.js'
import { encryptData, encryptSpan } from '../../src/encryption/stream-cipher.js'

const REF_SIZE = 64

function makeStorage() {
  const store = new Map<string, Uint8Array>()

  const put = (address: Uint8Array, data: Uint8Array) => store.set(uint8ArrayToHex(address), data)

  async function onBatch(entries: ChunkEntry[]): Promise<ChunkEntry[]> {
    for (const { chunk, key } of entries) {
      const { address } = chunk.encryptedHash(key)
      put(address.toUint8Array(), encryptLikeBee(chunk, key!, chunk.writer.buffer))
    }

    return []
  }

  async function fetch(address: Uint8Array): Promise<Uint8Array> {
    const data = store.get(uint8ArrayToHex(address))
    if (!data) throw new Error(`not found: ${uint8ArrayToHex(address)}`)

    return data
  }

  return { put, onBatch, fetch }
}

function encryptLikeBee(chunk: ChunkBuilder, key: Uint8Array, plaintext: Uint8Array): Uint8Array {
  const padding = crypto.getRandomValues(new Uint8Array(4096 - plaintext.length))

  return Bytes.concat(encryptSpan(key, numberToUint64(chunk.span, 'LE')), encryptData(key, plaintext), padding)
}

async function beeStyleEncryptedTree(data: Uint8Array) {
  const storage = makeStorage()
  const splitter = new ChunkSplitter(storage.onBatch, undefined, true)
  await splitter.append(data)
  const root = await splitter.finalize()

  const childCount = Math.ceil(data.length / 4096)
  const refs = root.writer.buffer.subarray(0, childCount * REF_SIZE)
  const key = crypto.getRandomValues(new Uint8Array(32))
  const rootChunk = encryptLikeBee(root, key, refs)
  const address = calculateChunkAddress(rootChunk).toUint8Array()
  storage.put(address, rootChunk)

  return { address, key, fetch: storage.fetch }
}

describe('joining an encrypted tree whose intermediate chunks Bee padded with random bytes', () => {
  it.each([4097, 4096 * 2, 4096 * 5 + 777])('reads back %i bytes', async length => {
    const data = Uint8Array.from({ length }, (_, i) => (i * 7 + 3) & 0xff)
    const { address, key, fetch } = await beeStyleEncryptedTree(data)

    expect(await ChunkJoiner.collectEncrypted(address, key, fetch)).toEqual(data)
  })
})
