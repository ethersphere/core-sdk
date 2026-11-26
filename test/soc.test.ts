import { describe, expect, it } from 'vitest'
import { uint256ToNumber, uint8ArrayToHex } from '../src/bytes/encoding.js'
import { makeContentAddressedChunk } from '../src/chunk/cac.js'
import {
  makeEncryptedReplicas,
  makeReplicas,
  makeSingleOwnerChunk,
  makeSOCAddress,
  REPLICAS_OWNER,
  unmarshalSingleOwnerChunk,
} from '../src/chunk/soc.js'
import { ChunkTreeBuilder } from '../src/chunk/builder.js'
import { ChunkSplitter } from '../src/chunk/chunk-splitter.js'
import { privateKeyToPublicKey, publicKeyToAddress } from '../src/crypto/keys.js'

// A fixed non-zero test private key, distinct from the REPLICAS_PRIVATE_KEY
// used internally for dispersed replicas.
const TEST_PRIVATE_KEY = 0x1234567890abcdefn

describe('REPLICAS_OWNER', () => {
  it('is the address derived from the documented fixed private key [1, 0, ..., 0]', () => {
    const key = new Uint8Array(32)
    key[0] = 1
    const privateKey = uint256ToNumber(key, 'BE')
    const derivedAddress = publicKeyToAddress(privateKeyToPublicKey(privateKey))
    expect(uint8ArrayToHex(derivedAddress)).toBe(uint8ArrayToHex(REPLICAS_OWNER))
  })

  it('is 20 bytes', () => {
    expect(REPLICAS_OWNER.length).toBe(20)
  })
})

describe('makeSOCAddress', () => {
  it('is deterministic for the same identifier and owner', () => {
    const identifier = new Uint8Array(32).fill(7)
    const owner = publicKeyToAddress(privateKeyToPublicKey(TEST_PRIVATE_KEY))
    expect(makeSOCAddress(identifier, owner).toHex()).toBe(makeSOCAddress(identifier, owner).toHex())
  })

  it('differs when the identifier changes', () => {
    const owner = publicKeyToAddress(privateKeyToPublicKey(TEST_PRIVATE_KEY))
    const a = makeSOCAddress(new Uint8Array(32).fill(1), owner)
    const b = makeSOCAddress(new Uint8Array(32).fill(2), owner)
    expect(a.toHex()).not.toBe(b.toHex())
  })
})

describe('makeSingleOwnerChunk / unmarshalSingleOwnerChunk', () => {
  it('round-trips a CAC-wrapped SOC', () => {
    const payload = Uint8Array.from({ length: 100 }, (_, i) => i)
    const cac = makeContentAddressedChunk(payload)
    const identifier = new Uint8Array(32).fill(9)

    const soc = makeSingleOwnerChunk(cac, identifier, TEST_PRIVATE_KEY)
    const expectedOwner = publicKeyToAddress(privateKeyToPublicKey(TEST_PRIVATE_KEY))

    expect(soc.owner.toHex()).toBe(uint8ArrayToHex(expectedOwner))
    expect(soc.address.toHex()).toBe(makeSOCAddress(identifier, expectedOwner).toHex())

    const unmarshalled = unmarshalSingleOwnerChunk(soc.data, soc.address)
    expect(unmarshalled.owner.toHex()).toBe(soc.owner.toHex())
    expect(unmarshalled.address.toHex()).toBe(soc.address.toHex())
    expect(unmarshalled.payload.toUint8Array()).toEqual(payload)
    expect(unmarshalled.span.toBigInt()).toBe(cac.span.toBigInt())
  })

  it('throws when the data does not match the given address', () => {
    const payload = Uint8Array.from({ length: 50 }, (_, i) => i)
    const cac = makeContentAddressedChunk(payload)
    const identifier = new Uint8Array(32).fill(3)
    const soc = makeSingleOwnerChunk(cac, identifier, TEST_PRIVATE_KEY)

    const wrongAddress = makeSOCAddress(new Uint8Array(32).fill(4), soc.owner)
    expect(() => unmarshalSingleOwnerChunk(soc.data, wrongAddress)).toThrow()
  })
})

describe('makeReplicas', () => {
  it('returns an empty array for redundancy level 0 (NONE)', async () => {
    const root = await ChunkSplitter.root(new Uint8Array(100).fill(1))
    expect(makeReplicas(root, 0)).toEqual([])
  })

  it.each([
    [1, 2],
    [2, 4],
    [3, 8],
    [4, 16],
  ])('produces level-%i redundancy as %i verifiable, owned replicas', async (level, expectedCount) => {
    const payload = Uint8Array.from({ length: 500 }, (_, i) => (i * 3) % 256)
    const root = await ChunkSplitter.root(payload)

    const replicas = makeReplicas(root, level)
    expect(replicas).toHaveLength(expectedCount)

    const addresses = new Set<string>()
    for (const replica of replicas) {
      const soc = unmarshalSingleOwnerChunk(replica.data, replica.address)
      expect(soc.owner.toUint8Array()).toEqual(REPLICAS_OWNER)
      // ChunkBuilder always carries the full zero-padded 4096-byte buffer as
      // its payload - span is what marks the real content length.
      expect(soc.span.toBigInt()).toBe(BigInt(payload.length))
      expect(soc.payload.toUint8Array().subarray(0, payload.length)).toEqual(payload)
      addresses.add(replica.address.toHex())
    }
    // every replica lands in a distinct neighbourhood, so addresses are unique
    expect(addresses.size).toBe(expectedCount)
  })
})

describe('makeEncryptedReplicas', () => {
  it('returns an empty array for redundancy level 0 (NONE)', async () => {
    const root = await ChunkSplitter.root(new Uint8Array(100).fill(1))
    const key = new Uint8Array(32).fill(5)
    expect(makeEncryptedReplicas(root, key, 0)).toEqual([])
  })

  it('produces verifiable, owned replicas wrapping the encrypted body', async () => {
    const payload = Uint8Array.from({ length: 4096 * 2 + 42 }, (_, i) => (i * 5 + 1) % 256)
    const splitter = new ChunkTreeBuilder(ChunkTreeBuilder.NOOP, undefined, true)
    await splitter.append(payload)
    const root = await splitter.finalize()
    const key = new Uint8Array(32).fill(6)

    const replicas = makeEncryptedReplicas(root, key, 2)
    expect(replicas).toHaveLength(4)

    for (const replica of replicas) {
      const soc = unmarshalSingleOwnerChunk(replica.data, replica.address)
      expect(soc.owner.toUint8Array()).toEqual(REPLICAS_OWNER)
      expect(soc.address.toHex()).toBe(replica.address.toHex())
    }
  })
})
