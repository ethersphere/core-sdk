import { describe, expect, it } from 'vitest'
import { Bytes } from '../src/bytes/bytes.js'
import { hexToUint8Array, uint8ArrayToHex } from '../src/bytes/encoding.js'
import { calculateChunkAddress } from '../src/chunk/bmt.js'
import { DataSplitter, SplitChunk } from '../src/chunk/data-splitter.js'
import { ChunkJoiner } from '../src/chunk/joiner.js'
import { REPLICAS_OWNER, unmarshalSingleOwnerChunk } from '../src/chunk/soc.js'
import { keccak256 } from '../src/crypto/keccak.js'

const BEE_VECTORS = [
  {
    size: 100,
    level: 0,
    root: '93dc8e7f215f3de6f960239d5dd0ef4e90a94ddb31922e05e3ef649f3effc3c7',
    chunkCount: 1,
    digest: 'c183a2d659f4bacfe1de2d8794007e49ef39c48cbd3ad745d2dd48363b963678',
  },
  {
    size: 100,
    level: 1,
    root: '93dc8e7f215f3de6f960239d5dd0ef4e90a94ddb31922e05e3ef649f3effc3c7',
    chunkCount: 3,
    digest: '62b418b0cb9d9d7d879d257b905882da91b098a267f40774003f3ec8af046521',
  },
  {
    size: 100,
    level: 2,
    root: '93dc8e7f215f3de6f960239d5dd0ef4e90a94ddb31922e05e3ef649f3effc3c7',
    chunkCount: 5,
    digest: '08d4b0c837f0bf58890a823a388a4908d83bc4943f09806d19b3ab1ef83bf773',
  },
  {
    size: 100,
    level: 3,
    root: '93dc8e7f215f3de6f960239d5dd0ef4e90a94ddb31922e05e3ef649f3effc3c7',
    chunkCount: 9,
    digest: 'bcbfc251b76d2a38d2f1bb43a0acc91c2ffc3ff90dfc42455851dabf26d4398f',
  },
  {
    size: 100,
    level: 4,
    root: '93dc8e7f215f3de6f960239d5dd0ef4e90a94ddb31922e05e3ef649f3effc3c7',
    chunkCount: 17,
    digest: 'ff09f5157496ba71e3c747bc22a1c57179f184c31155752265c6b6d2b1291235',
  },
  {
    size: 819323,
    level: 0,
    root: '76c0d3b3dfd48fec3fed0988d31028544d206176b1488a50a5b8d288012ded7b',
    chunkCount: 204,
    digest: 'a182392ef2d1086e2ce52f755a0056cf3d6173eee56e5f48cbbfba9fbf6e73f5',
  },
  {
    size: 819323,
    level: 1,
    root: '882343f694832d3555373da8134a2529a3173f00606e8391e4cc048cce16b91a',
    chunkCount: 226,
    digest: '747ff09e770e229d9ae8a09b59dcd8f3356d2897b9450a10bf2d9c20fc095d2c',
  },
  {
    size: 819323,
    level: 2,
    root: 'd7d571eae551151046dd280b6b3b8e455b3ca68044e6e31566896302a5876279',
    chunkCount: 253,
    digest: '5f57cf98a1d3830e3fdce4f7ab7aa7c74b0176c8b2a3338dd052a714e43d5748',
  },
  {
    size: 819323,
    level: 3,
    root: '9c4c671bd77f76a9807ee65f270cd64be3e175358aeb8f323f75970440e564cf',
    chunkCount: 291,
    digest: '7b2554fadcdafac63627aa51bd1cdbeb2c4d0c1da0322e03f01d265e9297d66b',
  },
  {
    size: 819323,
    level: 4,
    root: '77350ae5840db43d6373d3bb358043119f42e606d4ad8a62b43a8ef4ac7b3898',
    chunkCount: 737,
    digest: '34bd6443cdbbe382f05f871c1c1fb802b04ad6c5776449fd8004b8c03dee4fe7',
  },
]

const REPLICA_COUNTS = [0, 2, 4, 8, 16]

function payload(size: number): Uint8Array {
  return Uint8Array.from({ length: size }, (_, i) => (i * 7 + (i >> 12) * 13 + 3) % 256)
}

function makeStore() {
  const chunks = new Map<string, Uint8Array>()
  const emitted: SplitChunk[] = []

  async function onChunk(chunk: SplitChunk): Promise<void> {
    emitted.push(chunk)
    chunks.set(chunk.address.toHex(), chunk.data)
  }

  async function fetch(address: Uint8Array): Promise<Uint8Array> {
    const data = chunks.get(uint8ArrayToHex(address))
    if (!data) throw new Error(`not found: ${uint8ArrayToHex(address)}`)

    return data
  }

  function digest(): string {
    const entries = [...chunks.keys()]
      .sort()
      .map(address => Bytes.concat(hexToUint8Array(address), keccak256(chunks.get(address)!)))

    return uint8ArrayToHex(keccak256(Bytes.concat(...entries)))
  }

  return { chunks, emitted, onChunk, fetch, digest }
}

function isReplica(chunk: SplitChunk): boolean {
  return chunk.data.length > 105 && !calculateChunkAddress(chunk.data.subarray(0, 4104)).equals(chunk.address)
}

describe('DataSplitter', () => {
  it.each(BEE_VECTORS)(
    'emits the same chunks as Bee for $size bytes at redundancy level $level',
    async ({ size, level, root, chunkCount, digest }) => {
      const store = makeStore()

      const reference = await DataSplitter.split(payload(size), { redundancyLevel: level, onChunk: store.onChunk })

      expect(reference.toHex()).toBe(root)
      expect(store.chunks.size).toBe(chunkCount)
      expect(store.digest()).toBe(digest)
    },
  )

  it.each([0, 1, 2, 3, 4])('round-trips through ChunkJoiner at redundancy level %i', async level => {
    const store = makeStore()
    const data = payload(4096 * 150 + 77)

    const reference = await DataSplitter.split(data, { redundancyLevel: level, onChunk: store.onChunk })

    expect(await ChunkJoiner.collect(reference.toUint8Array(), store.fetch)).toEqual(data)
  })

  it.each([0, 1, 2, 3, 4])('round-trips an encrypted payload at redundancy level %i', async level => {
    const store = makeStore()
    const data = payload(4096 * 80 + 5)

    const reference = await DataSplitter.split(data, {
      encrypted: true,
      redundancyLevel: level,
      onChunk: store.onChunk,
    })
    const bytes = reference.toUint8Array()

    expect(bytes).toHaveLength(64)
    expect(await ChunkJoiner.collectEncrypted(bytes.subarray(0, 32), bytes.subarray(32), store.fetch)).toEqual(data)
  })

  it.each([false, true])('emits only chunks whose data matches their address (encrypted: %s)', async encrypted => {
    const store = makeStore()

    await DataSplitter.split(payload(4096 * 40 + 9), { encrypted, redundancyLevel: 2, onChunk: store.onChunk })

    for (const chunk of store.emitted) {
      if (isReplica(chunk)) {
        expect(unmarshalSingleOwnerChunk(chunk.data, chunk.address).owner.toUint8Array()).toEqual(REPLICAS_OWNER)
      } else {
        expect(calculateChunkAddress(chunk.data).toHex()).toBe(chunk.address.toHex())
      }
    }
  })

  it.each([0, 1, 2, 3, 4])('emits the root chunk and %i-level replicas of it', async level => {
    const store = makeStore()

    const reference = await DataSplitter.split(payload(4096 * 3), { redundancyLevel: level, onChunk: store.onChunk })
    const replicas = store.emitted.filter(isReplica)

    expect(store.emitted.filter(chunk => chunk.address.equals(reference))).toHaveLength(1)
    expect(replicas).toHaveLength(REPLICA_COUNTS[level]!)
    for (const replica of replicas) {
      expect(calculateChunkAddress(unmarshalSingleOwnerChunk(replica.data, replica.address).data.subarray(97))).toEqual(
        reference,
      )
    }
  })

  it('emits encrypted root replicas wrapping the encrypted root chunk', async () => {
    const store = makeStore()

    const reference = await DataSplitter.split(payload(500), {
      encrypted: true,
      redundancyLevel: 3,
      onChunk: store.onChunk,
    })
    const rootAddress = reference.toUint8Array().subarray(0, 32)
    const replicas = store.emitted.filter(isReplica)

    expect(replicas).toHaveLength(8)
    for (const replica of replicas) {
      const wrapped = unmarshalSingleOwnerChunk(replica.data, replica.address).data.subarray(97)
      expect(wrapped).toEqual(store.chunks.get(uint8ArrayToHex(rootAddress)))
    }
  })

  it('produces the same chunks when data is appended in parts', async () => {
    const data = payload(4096 * 70 + 1234)
    const oneShot = makeStore()
    const streamed = makeStore()

    const expected = await DataSplitter.split(data, { redundancyLevel: 2, onChunk: oneShot.onChunk })
    const splitter = new DataSplitter({ redundancyLevel: 2, onChunk: streamed.onChunk })
    for (let offset = 0; offset < data.length; offset += 10_000) {
      await splitter.append(data.subarray(offset, offset + 10_000))
    }
    const reference = await splitter.finalize()

    expect(reference.toHex()).toBe(expected.toHex())
    expect(streamed.digest()).toBe(oneShot.digest())
  })

  it('splits empty data into a single empty root chunk', async () => {
    const store = makeStore()

    const reference = await DataSplitter.split(new Uint8Array(0), { onChunk: store.onChunk })

    expect(store.emitted).toHaveLength(1)
    expect(store.emitted[0]!.data).toEqual(new Uint8Array(8))
    expect(await ChunkJoiner.collect(reference.toUint8Array(), store.fetch)).toEqual(new Uint8Array(0))
  })

  it('defaults to no encryption and no redundancy', async () => {
    const store = makeStore()

    const reference = await DataSplitter.split(payload(100), { onChunk: store.onChunk })

    expect(reference.toHex()).toBe(BEE_VECTORS[0]!.root)
    expect(store.emitted).toHaveLength(1)
  })

  it.each([-1, 5, 1.5, Number.NaN])('rejects redundancy level %s', level => {
    expect(() => new DataSplitter({ redundancyLevel: level, onChunk: async () => {} })).toThrow(
      new RangeError(`Redundancy level out of range: ${level}`),
    )
  })

  it('rejects appending after finalize', async () => {
    const splitter = new DataSplitter({ onChunk: async () => {} })
    await splitter.finalize()

    await expect(splitter.append(new Uint8Array(1))).rejects.toThrow('DataSplitter is already finalized')
  })

  it('rejects finalizing twice', async () => {
    const splitter = new DataSplitter({ onChunk: async () => {} })
    await splitter.finalize()

    await expect(splitter.finalize()).rejects.toThrow('DataSplitter is already finalized')
  })
})
