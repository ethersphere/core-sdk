import { Bytes } from '../bytes/bytes.js'
import { concatBytes, hexToUint8Array, numberToUint256, numberToUint64, uint256ToNumber } from '../bytes/encoding.js'
import { EthAddress } from '../bytes/eth-address.js'
import { Identifier } from '../bytes/identifier.js'
import { Reference } from '../bytes/reference.js'
import { Signature } from '../bytes/signature.js'
import { Span } from '../bytes/span.js'
import { recoverPublicKey, signMessage } from '../crypto/ecdsa.js'
import { keccak256 } from '../crypto/keccak.js'
import { privateKeyToPublicKey, publicKeyToAddress } from '../crypto/keys.js'
import { encryptData, encryptSpan } from '../encryption/stream-cipher.js'
import { calculateChunkAddress } from './bmt.js'
import type { Chunk } from './cac.js'
import { ChunkBuilder } from './splitter.js'

/**
 * Ethereum address derived from the fixed replicas private key below -
 * constant across all Bee nodes.
 */
export const REPLICAS_OWNER = hexToUint8Array('dc5b20847f43d67928f49cd4f85d696b5a7617b5')

// Private key with byte 0 = 1 (big-endian), i.e. 2^248 - the fixed signer
// used for all dispersed replicas. Its address is REPLICAS_OWNER above.
const REPLICAS_PRIVATE_KEY = 1n << 248n

const SIGNATURE_LENGTH = 65
const SOC_SIGNATURE_OFFSET = Identifier.LENGTH
const SOC_SPAN_OFFSET = Identifier.LENGTH + SIGNATURE_LENGTH
const SOC_PAYLOAD_OFFSET = SOC_SPAN_OFFSET + Span.LENGTH

const ETHEREUM_SIGNED_MESSAGE_PREFIX = new TextEncoder().encode('\x19Ethereum Signed Message:\n32')

// Replica counts per redundancy level: NONE=0, MEDIUM=2, STRONG=4, INSANE=8, PARANOID=16.
const REPLICA_COUNTS = [0, 2, 4, 8, 16]

// Base offsets for neighbourhood index computation, one per erasure level 1..4.
const NEIGHBOURHOOD_BASES = [0, 2, 6, 14]

/**
 * Single Owner Chunk (SOC) - a chunk type where the address is determined by
 * the owner and an arbitrary identifier. Its integrity is attested by the
 * owner's digital signature rather than by hashing the content directly.
 *
 * - `span` indicates the size of the `payload` in bytes.
 * - `payload` contains the actual data or the body of the chunk.
 * - `data` contains the full chunk data - `identifier`, `signature`, `span` and `payload`.
 * - `address` is the Swarm hash (or reference) of the chunk.
 * - `identifier` is an arbitrary identifier selected by the uploader.
 * - `signature` is the 65-byte (r || s || v) signature of the owner over the identifier and the wrapped chunk's address.
 * - `owner` is the Ethereum address of the chunk owner.
 */
export interface SingleOwnerChunk {
  readonly data: Uint8Array
  span: Span
  payload: Bytes
  address: Reference
  identifier: Identifier
  signature: Signature
  owner: EthAddress
}

function socSigningDigest(identifier: Uint8Array, cacAddress: Uint8Array): Uint8Array {
  const toSign = keccak256(concatBytes(identifier, cacAddress))

  return concatBytes(ETHEREUM_SIGNED_MESSAGE_PREFIX, toSign)
}

function signSoc(identifier: Uint8Array, cacAddress: Uint8Array, privateKey: bigint): Uint8Array {
  const [r, s, v] = signMessage(socSigningDigest(identifier, cacAddress), privateKey)

  return concatBytes(numberToUint256(r, 'BE'), numberToUint256(s, 'BE'), new Uint8Array([Number(v)]))
}

function recoverSocOwner(identifier: Uint8Array, cacAddress: Uint8Array, signature: Uint8Array): Uint8Array {
  const r = uint256ToNumber(signature.subarray(0, 32), 'BE')
  const s = uint256ToNumber(signature.subarray(32, 64), 'BE')
  const v = BigInt(signature[64]!) as 27n | 28n
  const publicKey = recoverPublicKey(socSigningDigest(identifier, cacAddress), r, s, v)

  return publicKeyToAddress(publicKey)
}

/**
 * SOC address = keccak256(identifier || owner).
 */
export function makeSOCAddress(
  identifier: Identifier | Uint8Array | string,
  owner: EthAddress | Uint8Array | string,
): Reference {
  const id = new Identifier(identifier)
  const ownerAddress = new EthAddress(owner)

  return new Reference(keccak256(concatBytes(id.toUint8Array(), ownerAddress.toUint8Array())))
}

/**
 * Wraps a Content Addressed Chunk in a Single Owner Chunk, signed by
 * `privateKey` over the identifier and the wrapped chunk's address.
 */
export function makeSingleOwnerChunk(
  chunk: Pick<Chunk, 'data' | 'span' | 'payload' | 'address'>,
  identifier: Identifier | Uint8Array | string,
  privateKey: bigint,
): SingleOwnerChunk {
  const id = new Identifier(identifier)
  const signature = signSoc(id.toUint8Array(), chunk.address.toUint8Array(), privateKey)
  const owner = new EthAddress(publicKeyToAddress(privateKeyToPublicKey(privateKey)))
  const address = makeSOCAddress(id, owner)
  const data = concatBytes(id.toUint8Array(), signature, chunk.data)

  return {
    data,
    identifier: id,
    signature: new Signature(signature),
    span: chunk.span,
    payload: chunk.payload,
    address,
    owner,
  }
}

/**
 * Unmarshals arbitrary data into a Single Owner Chunk, verifying that the
 * recovered owner's SOC address matches the given address.
 * Throws if the data is not a valid SOC for that address.
 */
export function unmarshalSingleOwnerChunk(
  data: Bytes | Uint8Array,
  address: Reference | Uint8Array | string,
): SingleOwnerChunk {
  const bytes = data instanceof Bytes ? data.toUint8Array() : data
  const expectedAddress = new Reference(address)
  const identifier = new Identifier(Bytes.fromSlice(bytes, 0, Identifier.LENGTH))
  const signature = bytes.slice(SOC_SIGNATURE_OFFSET, SOC_SIGNATURE_OFFSET + SIGNATURE_LENGTH)
  const cacAddress = calculateChunkAddress(bytes.slice(SOC_SPAN_OFFSET))
  const owner = new EthAddress(recoverSocOwner(identifier.toUint8Array(), cacAddress.toUint8Array(), signature))
  const socAddress = makeSOCAddress(identifier, owner)

  if (!socAddress.equals(expectedAddress)) {
    throw new Error('SOC data does not match given address')
  }

  const span = Span.fromSlice(bytes, SOC_SPAN_OFFSET)
  const payload = Bytes.fromSlice(bytes, SOC_PAYLOAD_OFFSET)

  return {
    data: bytes,
    identifier,
    signature: new Signature(signature),
    span,
    payload,
    address: socAddress,
    owner,
  }
}

/**
 * Returns the neighbourhood index used to disperse replicas:
 * replicaIndexBases[d-1] + (addr[0] >> (8 - d)), where d = redundancyLevel (1..4).
 */
function neighbourhoodIndex(redundancyLevel: number, address: Uint8Array): number {
  return NEIGHBOURHOOD_BASES[redundancyLevel - 1]! + (address[0]! >> (8 - redundancyLevel))
}

/**
 * Computes the SOC identifiers for all dispersed replicas of a root chunk at
 * the given redundancy level.
 *
 * Each identifier is the root address with byte 0 replaced by an incrementing
 * counter. The first identifier landing in each distinct neighbourhood is
 * kept, until enough identifiers are collected.
 */
function replicaIdentifiers(rootAddress: Uint8Array, redundancyLevel: number): Uint8Array[] {
  const count = REPLICA_COUNTS[redundancyLevel]!
  if (count === 0) return []

  const covered = new Set<number>()
  const identifiers: Uint8Array[] = []

  for (let i = 0; i < 255 && identifiers.length < count; i++) {
    const identifier = new Uint8Array(32)
    identifier.set(rootAddress)
    identifier[0] = i

    const address = makeSOCAddress(identifier, REPLICAS_OWNER).toUint8Array()
    const neighbourhood = neighbourhoodIndex(redundancyLevel, address)

    if (!covered.has(neighbourhood)) {
      covered.add(neighbourhood)
      identifiers.push(identifier)
    }
  }

  return identifiers
}

/**
 * Creates all dispersed replica SOC chunks for the given root chunk, signed
 * by the well-known REPLICAS_OWNER key. Returns an empty array when
 * redundancyLevel is 0 (NONE).
 */
export function makeReplicas(
  rootChunk: ChunkBuilder,
  redundancyLevel: number,
): Array<{ address: Reference; data: Uint8Array }> {
  if (redundancyLevel === 0) return []

  const rootAddress = rootChunk.hash().toUint8Array()
  const identifiers = replicaIdentifiers(rootAddress, redundancyLevel)

  return identifiers.map(identifier => {
    const signature = signSoc(identifier, rootAddress, REPLICAS_PRIVATE_KEY)
    const data = concatBytes(identifier, signature, rootChunk.build())

    return { address: makeSOCAddress(identifier, REPLICAS_OWNER), data }
  })
}

/**
 * Creates dispersed replica SOC chunks for an *encrypted* root chunk: the
 * replica wraps the encrypted span + payload, and identifiers are derived
 * from the encrypted chunk's address rather than the plaintext one.
 */
export function makeEncryptedReplicas(
  rootChunk: ChunkBuilder,
  key: Uint8Array,
  redundancyLevel: number,
): Array<{ address: Reference; data: Uint8Array }> {
  if (redundancyLevel === 0) return []

  const encryptedAddress = rootChunk.encryptedHash(key).address.toUint8Array()
  const identifiers = replicaIdentifiers(encryptedAddress, redundancyLevel)
  const encryptedBody = concatBytes(
    encryptSpan(key, numberToUint64(rootChunk.span, 'LE')),
    encryptData(key, rootChunk.writer.buffer),
  )

  return identifiers.map(identifier => {
    const signature = signSoc(identifier, encryptedAddress, REPLICAS_PRIVATE_KEY)
    const data = concatBytes(identifier, signature, encryptedBody)

    return { address: makeSOCAddress(identifier, REPLICAS_OWNER), data }
  })
}
