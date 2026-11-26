import { describe, expect, it } from 'vitest'
import { Bytes } from '../src/bytes/bytes.js'
import { hexToUint8Array, numberToUint64, uint8ArrayToHex } from '../src/bytes/encoding.js'
import { makeContentAddressedChunk } from '../src/chunk/cac.js'
import { ChunkJoiner } from '../src/chunk/joiner.js'
import { makeEncryptedReplicas, makeReplicas, makeSingleOwnerChunk } from '../src/chunk/soc.js'
import { ChunkBuilder, ChunkEntry, ChunkTreeBuilder } from '../src/chunk/builder.js'
import { ChunkSplitter } from '../src/chunk/chunk-splitter.js'
import { encryptData, encryptSpan } from '../src/encryption/stream-cipher.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../src/erasure-coding/batch.js'
import { getMaxShards } from '../src/erasure-coding/levels.js'

const REPLICAS_PRIVATE_KEY = 1n << 248n
const OTHER_PRIVATE_KEY = 0x1234567890abcdefn

const BEE_ROOT = {
  address: 'f2fd372268d5c8140d14138904a90fb1106413dd756e572a62b49d358452e3a9',
  payload: 'core-sdk joiner integrity check',
}

const BEE_MEDIUM_REPLICAS = [
  '01fd372268d5c8140d14138904a90fb1106413dd756e572a62b49d358452e3a9879203f36fa92357877682cd150e396c62acf4931555449284b8f873e5bdcd93501503a88e65ebbafcd6e0cf2077fb2da312f8bc13aaf0f92b97d956b56935241c1f00000000000000636f72652d73646b206a6f696e657220696e7465677269747920636865636b',
  '00fd372268d5c8140d14138904a90fb1106413dd756e572a62b49d358452e3a91ec0ee9d2e1adcfeba22a4885e09e3106256c0b302993e5a47e05049247941205ac8fb4414d2bf5c5e2de24c570b7d0ef7cb32153e22175d02fb544a14d076e31b1f00000000000000636f72652d73646b206a6f696e657220696e7465677269747920636865636b',
]

function makeStorage() {
  const store = new Map<string, Uint8Array>()

  function put(address: Uint8Array, data: Uint8Array) {
    store.set(uint8ArrayToHex(address), data)
  }

  function putChunk(chunk: ChunkBuilder, key?: Uint8Array): Uint8Array {
    if (!key) {
      const address = chunk.hash().toUint8Array()
      put(address, chunk.build())

      return address
    }
    const { address } = chunk.encryptedHash(key)
    put(
      address.toUint8Array(),
      Bytes.concat(encryptSpan(key, numberToUint64(chunk.span, 'LE')), encryptData(key, chunk.writer.buffer)),
    )

    return address.toUint8Array()
  }

  async function onBatch(entries: ChunkEntry[]): Promise<ChunkEntry[]> {
    for (const { chunk, key } of entries) {
      putChunk(chunk, key)
    }

    return []
  }

  function tamper(address: Uint8Array, offset: number) {
    const data = store.get(uint8ArrayToHex(address))!.slice()
    data[offset]! ^= 0xff
    put(address, data)
  }

  async function fetch(address: Uint8Array): Promise<Uint8Array> {
    const data = store.get(uint8ArrayToHex(address))
    if (!data) throw new Error(`not found: ${uint8ArrayToHex(address)}`)

    return data
  }

  return { put, putChunk, onBatch, tamper, fetch }
}

const multiChunkData = Uint8Array.from({ length: 4096 * 3 + 321 }, (_, i) => (i * 7 + 3) % 256)

async function storeTree(data: Uint8Array) {
  const storage = makeStorage()
  const splitter = new ChunkTreeBuilder(storage.onBatch)
  await splitter.append(data)
  const rootChunk = await splitter.finalize()
  const root = storage.putChunk(rootChunk)

  return { storage, root, rootChunk }
}

async function storeEncryptedTree(data: Uint8Array) {
  const storage = makeStorage()
  const splitter = new ChunkTreeBuilder(storage.onBatch, undefined, true)
  await splitter.append(data)
  const rootChunk = await splitter.finalize()
  const key = new Uint8Array(32).fill(7)
  const root = storage.putChunk(rootChunk, key)

  return { storage, root, rootChunk, key }
}

function firstLeafAddress(rootChunk: ChunkBuilder): Uint8Array {
  return rootChunk.writer.buffer.slice(0, 32)
}

describe('ChunkJoiner with verify enabled', () => {
  it('reconstructs a valid multi-chunk tree', async () => {
    const { storage, root } = await storeTree(multiChunkData)

    expect(await ChunkJoiner.collect(root, storage.fetch, { verify: true })).toEqual(multiChunkData)
  })

  it('reconstructs a valid encrypted tree', async () => {
    const { storage, root, key } = await storeEncryptedTree(multiChunkData)

    expect(await ChunkJoiner.collectEncrypted(root, key, storage.fetch, { verify: true })).toEqual(multiChunkData)
  })

  it('reconstructs a valid erasure-coded tree', async () => {
    const storage = makeStorage()
    const level = 2
    const onChunk = async (chunk: ChunkBuilder, key?: Uint8Array) => {
      storage.putChunk(chunk, key)
    }
    const maxShards = getMaxShards(level, false)
    const data = Uint8Array.from({ length: 4096 * (maxShards + 2) + 9 }, (_, i) => (i * 11) % 256)
    const splitter = new ChunkTreeBuilder(
      makeErasureBatch(level, false, onChunk),
      maxShards,
      false,
      makeIntermediateChunkHandler(level),
    )
    await splitter.append(data)
    const root = storage.putChunk(await splitter.finalize())

    expect(await ChunkJoiner.collect(root, storage.fetch, { verify: true })).toEqual(data)
  })

  it('accepts chunks built without trailing zero padding', async () => {
    const storage = makeStorage()
    const chunk = makeContentAddressedChunk(new TextEncoder().encode('short'))
    storage.put(chunk.address.toUint8Array(), chunk.data)

    const collected = await ChunkJoiner.collect(chunk.address.toUint8Array(), storage.fetch, { verify: true })
    expect(new TextDecoder().decode(collected)).toBe('short')
  })

  it('rejects a leaf with a tampered payload', async () => {
    const { storage, root, rootChunk } = await storeTree(multiChunkData)
    const leaf = firstLeafAddress(rootChunk)
    storage.tamper(leaf, 100)

    await expect(ChunkJoiner.collect(root, storage.fetch, { verify: true })).rejects.toThrow(
      `Chunk integrity check failed: ${uint8ArrayToHex(leaf)}`,
    )
  })

  it('rejects a root with a tampered span', async () => {
    const { storage, root } = await storeTree(multiChunkData)
    storage.tamper(root, 0)

    await expect(ChunkJoiner.collect(root, storage.fetch, { verify: true })).rejects.toThrow(
      `Chunk integrity check failed: ${uint8ArrayToHex(root)}`,
    )
  })

  it('rejects an intermediate chunk with a tampered child reference', async () => {
    const { storage, root } = await storeTree(multiChunkData)
    storage.tamper(root, 8)

    await expect(ChunkJoiner.collect(root, storage.fetch, { verify: true })).rejects.toThrow(
      `Chunk integrity check failed: ${uint8ArrayToHex(root)}`,
    )
  })

  it('rejects a tampered encrypted chunk before decrypting it', async () => {
    const { storage, root, key } = await storeEncryptedTree(multiChunkData)
    storage.tamper(root, 50)

    await expect(ChunkJoiner.collectEncrypted(root, key, storage.fetch, { verify: true })).rejects.toThrow(
      `Chunk integrity check failed: ${uint8ArrayToHex(root)}`,
    )
  })

  it('rejects data shorter than a span', async () => {
    const address = new Uint8Array(32).fill(1)
    const fetch = async () => new Uint8Array(7)

    await expect(ChunkJoiner.collect(address, fetch, { verify: true })).rejects.toThrow('Chunk integrity check failed')
  })

  it('rejects data longer than a full chunk', async () => {
    const { rootChunk } = await storeTree(new Uint8Array(100).fill(3))
    const address = rootChunk.hash().toUint8Array()
    const fetch = async () => Bytes.concat(rootChunk.build(), new Uint8Array(1))

    await expect(ChunkJoiner.collect(address, fetch, { verify: true })).rejects.toThrow('Chunk integrity check failed')
  })

  it('verifies through the constructor flag', async () => {
    const { storage, root, rootChunk } = await storeTree(multiChunkData)
    storage.tamper(firstLeafAddress(rootChunk), 100)
    const joiner = new ChunkJoiner(storage.fetch, async () => {}, false, true)

    await expect(joiner.join(root)).rejects.toThrow('Chunk integrity check failed')
  })
})

describe('ChunkJoiner with verify disabled', () => {
  it('passes a tampered leaf through by default', async () => {
    const { storage, root, rootChunk } = await storeTree(multiChunkData)
    storage.tamper(firstLeafAddress(rootChunk), 100)

    const collected = await ChunkJoiner.collect(root, storage.fetch)
    expect(collected).toHaveLength(multiChunkData.length)
    expect(collected).not.toEqual(multiChunkData)
  })
})

describe('ChunkJoiner verifying single owner chunks', () => {
  const payload = new TextEncoder().encode('wrapped by a single owner chunk')
  const wrapped = makeContentAddressedChunk(payload)

  function fetchFrom(data: Uint8Array) {
    return async () => data
  }

  it('unwraps a SOC fetched at its own address', async () => {
    const soc = makeSingleOwnerChunk(wrapped, new Uint8Array(32).fill(4), OTHER_PRIVATE_KEY)

    const collected = await ChunkJoiner.collect(soc.address.toUint8Array(), fetchFrom(soc.data), { verify: true })
    expect(collected).toEqual(payload)
  })

  it('rejects a SOC with a tampered signature', async () => {
    const soc = makeSingleOwnerChunk(wrapped, new Uint8Array(32).fill(4), OTHER_PRIVATE_KEY)
    const data = soc.data.slice()
    data[40]! ^= 0xff

    await expect(ChunkJoiner.collect(soc.address.toUint8Array(), fetchFrom(data), { verify: true })).rejects.toThrow(
      'Chunk integrity check failed',
    )
  })

  it('rejects a SOC with a tampered wrapped payload', async () => {
    const soc = makeSingleOwnerChunk(wrapped, new Uint8Array(32).fill(4), OTHER_PRIVATE_KEY)
    const data = soc.data.slice()
    data[data.length - 1]! ^= 0xff

    await expect(ChunkJoiner.collect(soc.address.toUint8Array(), fetchFrom(data), { verify: true })).rejects.toThrow(
      'Chunk integrity check failed',
    )
  })

  it('rejects a valid SOC served under another address', async () => {
    const soc = makeSingleOwnerChunk(wrapped, new Uint8Array(32).fill(4), OTHER_PRIVATE_KEY)

    await expect(
      ChunkJoiner.collect(wrapped.address.toUint8Array(), fetchFrom(soc.data), { verify: true }),
    ).rejects.toThrow('Chunk integrity check failed')
  })
})

describe('ChunkJoiner verifying dispersed replicas', () => {
  const beeRoot = hexToUint8Array(BEE_ROOT.address)

  it.each(BEE_MEDIUM_REPLICAS.map((replica, i) => [i, replica]))(
    'accepts Bee replica %i in place of the root chunk',
    async (_, replica) => {
      const fetch = async () => hexToUint8Array(replica)

      const collected = await ChunkJoiner.collect(beeRoot, fetch, { verify: true })
      expect(new TextDecoder().decode(collected)).toBe(BEE_ROOT.payload)
    },
  )

  it.each([1, 2, 3, 4])('accepts every level-%i replica made by makeReplicas', async level => {
    const rootChunk = await ChunkSplitter.root(new TextEncoder().encode(BEE_ROOT.payload))
    const root = rootChunk.hash().toUint8Array()

    for (const replica of makeReplicas(rootChunk, level)) {
      const collected = await ChunkJoiner.collect(root, async () => replica.data, { verify: true })
      expect(new TextDecoder().decode(collected)).toBe(BEE_ROOT.payload)
    }
  })

  it('accepts encrypted replicas in place of the encrypted root chunk', async () => {
    const { rootChunk, root, key } = await storeEncryptedTree(new Uint8Array(500).fill(5))

    for (const replica of makeEncryptedReplicas(rootChunk, key, 2)) {
      const collected = await ChunkJoiner.collectEncrypted(root, key, async () => replica.data, { verify: true })
      expect(collected).toEqual(new Uint8Array(500).fill(5))
    }
  })

  it('accepts a replica fetched at its own SOC address', async () => {
    const rootChunk = await ChunkSplitter.root(new TextEncoder().encode(BEE_ROOT.payload))
    const [replica] = makeReplicas(rootChunk, 1)

    const collected = await ChunkJoiner.collect(replica!.address.toUint8Array(), async () => replica!.data, {
      verify: true,
    })
    expect(new TextDecoder().decode(collected)).toBe(BEE_ROOT.payload)
  })

  it('rejects a replica whose identifier does not match the wrapped chunk address', async () => {
    const rootChunk = makeContentAddressedChunk(new TextEncoder().encode(BEE_ROOT.payload))
    const identifier = rootChunk.address.toUint8Array().slice()
    identifier[31]! ^= 0xff
    const replica = makeSingleOwnerChunk(rootChunk, identifier, REPLICAS_PRIVATE_KEY)

    await expect(
      ChunkJoiner.collect(rootChunk.address.toUint8Array(), async () => replica.data, { verify: true }),
    ).rejects.toThrow('Chunk integrity check failed')
    await expect(
      ChunkJoiner.collect(replica.address.toUint8Array(), async () => replica.data, { verify: true }),
    ).rejects.toThrow('Chunk integrity check failed')
  })

  it('rejects a replica-shaped SOC that is not signed by the replicas owner', async () => {
    const rootChunk = makeContentAddressedChunk(new TextEncoder().encode(BEE_ROOT.payload))
    const forged = makeSingleOwnerChunk(rootChunk, rootChunk.address.toUint8Array(), OTHER_PRIVATE_KEY)

    await expect(
      ChunkJoiner.collect(rootChunk.address.toUint8Array(), async () => forged.data, { verify: true }),
    ).rejects.toThrow('Chunk integrity check failed')
  })

  it('rejects a valid replica of a different chunk', async () => {
    const otherChunk = await ChunkSplitter.root(new TextEncoder().encode('some other root chunk'))
    const [replica] = makeReplicas(otherChunk, 1)

    await expect(ChunkJoiner.collect(beeRoot, async () => replica!.data, { verify: true })).rejects.toThrow(
      `Chunk integrity check failed: ${BEE_ROOT.address}`,
    )
  })
})
