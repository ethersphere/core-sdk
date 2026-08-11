import { Bytes } from '../bytes/bytes.js'
import { Identifier } from '../bytes/identifier.js'
import { PrivateKey } from '../bytes/private-key.js'
import { Reference } from '../bytes/reference.js'
import { Span } from '../bytes/span.js'
import { calculateChunkAddress } from './bmt.js'
import { makeSingleOwnerChunk, SingleOwnerChunk } from './soc.js'

/** Smallest payload a Content Addressed Chunk can hold, in bytes. */
export const MIN_PAYLOAD_SIZE = 1
/** Largest payload a Content Addressed Chunk can hold, in bytes. */
export const MAX_PAYLOAD_SIZE = 4096

/**
 * Content Addressed Chunk (CAC) - the immutable building block of Swarm,
 * holding at most 4096 bytes of payload.
 *
 * - `span` indicates the size of the `payload` in bytes.
 * - `payload` contains the actual data or the body of the chunk.
 * - `data` contains the full chunk data - `span` and `payload`.
 * - `address` is the Swarm hash (or reference) of the chunk.
 *
 * The `toSingleOwnerChunk` method allows converting the CAC into a Single Owner Chunk (SOC).
 */
export interface Chunk {
  readonly data: Uint8Array
  span: Span
  payload: Bytes
  address: Reference
  /**
   * Converts this CAC into a Single Owner Chunk (SOC), signed by `privateKey`
   * over `identifier` and this chunk's address.
   */
  toSingleOwnerChunk: (
    identifier: Identifier | Uint8Array | string,
    privateKey: PrivateKey | Uint8Array | string,
  ) => SingleOwnerChunk
}

/**
 * Builds a Content Addressed Chunk from a payload (at most 4096 bytes),
 * computing its BMT address. `span` defaults to the payload's own length -
 * pass it explicitly when wrapping a larger, already-spanned subtree.
 */
export function makeContentAddressedChunk(rawPayload: Bytes | Uint8Array | string, span?: Span | bigint): Chunk {
  if (typeof rawPayload === 'string') {
    rawPayload = Bytes.fromUtf8(rawPayload)
  }

  if (rawPayload.length < MIN_PAYLOAD_SIZE || rawPayload.length > MAX_PAYLOAD_SIZE) {
    throw new RangeError(`payload size ${rawPayload.length} exceeds limits [${MIN_PAYLOAD_SIZE}, ${MAX_PAYLOAD_SIZE}]`)
  }

  const typedSpan: Span = span
    ? typeof span === 'bigint'
      ? Span.fromBigInt(span)
      : span
    : Span.fromBigInt(BigInt(rawPayload.length))
  const payload = new Bytes(rawPayload)
  const data = Bytes.concat(typedSpan.toUint8Array(), payload.toUint8Array())
  const address = calculateChunkAddress(data)

  const chunk: Chunk = {
    data,
    span: typedSpan,
    payload,
    address,
    toSingleOwnerChunk: (identifier, privateKey) =>
      makeSingleOwnerChunk(chunk, identifier, new PrivateKey(privateKey).toBigInt()),
  }

  return chunk
}

/**
 * Parses raw chunk bytes (8-byte span || payload) into a Chunk, recomputing
 * its address.
 */
export function unmarshalContentAddressedChunk(data: Bytes | Uint8Array): Chunk {
  const bytes = new Bytes(data)

  return makeContentAddressedChunk(bytes.toUint8Array().slice(Span.LENGTH), Span.fromSlice(bytes.toUint8Array(), 0))
}
