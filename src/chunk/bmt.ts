import { partition } from '../bytes/encoding.js'
import { Reference } from '../bytes/reference.js'
import { keccak256 } from '../crypto/keccak.js'
import { Bytes } from '../bytes/bytes.js'

const MAX_CHUNK_PAYLOAD_SIZE = 4096
const SEGMENT_SIZE = 32
const SPAN_LENGTH = 8

/**
 * Calculate a Binary Merkle Tree hash for a chunk.
 *
 * The BMT chunk address is the hash of the 8-byte span and the root hash of
 * a binary Merkle tree (BMT) built on the 32-byte segments of the payload.
 *
 * If the payload is less than 4096 bytes, it's treated as if padded with
 * zeros up to 4096 bytes for the purposes of this calculation.
 *
 * @param chunkContent Chunk data, including the span and the payload.
 */
export function calculateChunkAddress(chunkContent: Uint8Array): Reference {
  const span = chunkContent.subarray(0, SPAN_LENGTH)
  const payload = chunkContent.subarray(SPAN_LENGTH)
  const rootHash = calculateBmtRootHash(payload)

  return new Reference(keccak256(Bytes.concat(span, rootHash)))
}

function calculateBmtRootHash(payload: Uint8Array): Uint8Array {
  if (payload.length > MAX_CHUNK_PAYLOAD_SIZE) {
    throw new Error(`payload size ${payload.length} exceeds maximum chunk payload size ${MAX_CHUNK_PAYLOAD_SIZE}`)
  }

  const input = new Uint8Array(MAX_CHUNK_PAYLOAD_SIZE)
  input.set(payload)

  let segments: Uint8Array[] = partition(input, SEGMENT_SIZE)
  while (segments.length > 1) {
    const next: Uint8Array[] = []
    for (let i = 0; i < segments.length; i += 2) {
      next.push(keccak256(Bytes.concat(segments[i]!, segments[i + 1]!)))
    }
    segments = next
  }

  return segments[0]!
}
