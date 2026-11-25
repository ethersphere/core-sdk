import { equals, uint8ArrayToHex } from '../bytes/encoding.js'
import { Identifier } from '../bytes/identifier.js'
import { Signature } from '../bytes/signature.js'
import { Span } from '../bytes/span.js'
import { calculateChunkAddress } from './bmt.js'
import { MAX_PAYLOAD_SIZE } from './cac.js'
import { makeSOCAddress, recoverSocOwner, REPLICAS_OWNER } from './soc.js'

const MAX_CHUNK_LENGTH = Span.LENGTH + MAX_PAYLOAD_SIZE
const SOC_HEADER_LENGTH = Identifier.LENGTH + Signature.LENGTH

export function verifyFetchedChunk(address: Uint8Array, raw: Uint8Array): Uint8Array {
  if (isContentAddressedChunkAt(address, raw)) {
    return raw
  }

  const wrapped = unwrapSingleOwnerChunkAt(address, raw)

  if (!wrapped) {
    throw new Error(`Chunk integrity check failed: ${uint8ArrayToHex(address)}`)
  }

  return wrapped
}

function isContentAddressedChunkAt(address: Uint8Array, raw: Uint8Array): boolean {
  return isChunkLength(raw.length) && equals(calculateChunkAddress(raw).toUint8Array(), address)
}

function unwrapSingleOwnerChunkAt(address: Uint8Array, raw: Uint8Array): Uint8Array | undefined {
  if (!isChunkLength(raw.length - SOC_HEADER_LENGTH)) {
    return undefined
  }

  const identifier = raw.subarray(0, Identifier.LENGTH)
  const signature = raw.subarray(Identifier.LENGTH, SOC_HEADER_LENGTH)
  const wrapped = raw.subarray(SOC_HEADER_LENGTH)
  const wrappedAddress = calculateChunkAddress(wrapped).toUint8Array()
  const owner = tryRecoverSocOwner(identifier, wrappedAddress, signature)

  if (!owner) {
    return undefined
  }

  if (!equals(owner, REPLICAS_OWNER)) {
    return makeSOCAddress(identifier, owner).equals(address) ? wrapped : undefined
  }

  // Bee only accepts a replica whose identifier matches the wrapped chunk address apart from byte 0.
  if (!equals(identifier.subarray(1), wrappedAddress.subarray(1))) {
    return undefined
  }

  const isReplicaOfAddress = equals(wrappedAddress, address)

  return isReplicaOfAddress || makeSOCAddress(identifier, owner).equals(address) ? wrapped : undefined
}

function isChunkLength(length: number): boolean {
  return length >= Span.LENGTH && length <= MAX_CHUNK_LENGTH
}

function tryRecoverSocOwner(
  identifier: Uint8Array,
  wrappedAddress: Uint8Array,
  signature: Uint8Array,
): Uint8Array | undefined {
  try {
    return recoverSocOwner(identifier, wrappedAddress, signature)
  } catch {
    return undefined
  }
}
