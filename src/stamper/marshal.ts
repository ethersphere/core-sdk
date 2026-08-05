import { concatBytes } from '../bytes/encoding.js'
import { BatchId } from '../bytes/batch-id.js'
import { Bytes } from '../bytes/bytes.js'
import { EthAddress } from '../bytes/eth-address.js'
import { Signature } from '../bytes/signature.js'

/** A postage stamp's fields, as produced by signing (e.g. via `stamp()`). */
export interface Envelope {
  issuer: EthAddress
  index: Uint8Array
  timestamp: Uint8Array
  signature: Signature
}

/** An {@link Envelope} with its batch ID, ready to marshal. */
export interface EnvelopeWithBatchId extends Envelope {
  batchId: BatchId
}

/**
 * Marshals a postage stamp's fields into the wire format Bee expects:
 * `batchId (32) || index (8) || timestamp (8) || signature (65)`.
 */
export function marshalStamp(
  signature: Uint8Array,
  batchId: Uint8Array,
  timestamp: Uint8Array,
  index: Uint8Array,
): Bytes {
  if (signature.length !== 65) {
    throw new Error('invalid signature length')
  }
  if (batchId.length !== 32) {
    throw new Error('invalid batch ID length')
  }
  if (timestamp.length !== 8) {
    throw new Error('invalid timestamp length')
  }
  if (index.length !== 8) {
    throw new Error('invalid index length')
  }
  return new Bytes(concatBytes(batchId, index, timestamp, signature))
}

/**
 * Same as {@link marshalStamp}, taking the fields from an EnvelopeWithBatchId.
 */
export function convertEnvelopeToMarshaledStamp(envelope: EnvelopeWithBatchId): Bytes {
  return marshalStamp(
    envelope.signature.toUint8Array(),
    envelope.batchId.toUint8Array(),
    envelope.timestamp,
    envelope.index,
  )
}
