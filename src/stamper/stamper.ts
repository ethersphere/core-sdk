import { BatchId } from '../bytes/batch-id.js'
import { concatBytes, numberToUint32, numberToUint64, uint16ToNumber } from '../bytes/encoding.js'
import { PrivateKey } from '../bytes/private-key.js'
import { EnvelopeWithBatchId } from './marshal.js'

/**
 * Signs a single chunk address into a postage stamp envelope.
 *
 * `slot` is the chunk's position within its bucket (the top 16 bits of its
 * address) - callers tracking their own bucket state pick this themselves.
 * `Stamper` below tracks it automatically instead.
 */
export function stamp(
  signer: PrivateKey | Uint8Array | string,
  batchId: BatchId | Uint8Array | string,
  address: Uint8Array,
  slot: number,
  timestampMs: number = Date.now(),
): EnvelopeWithBatchId {
  const privateKey = new PrivateKey(signer)
  const batch = new BatchId(batchId)
  const bucket = uint16ToNumber(address, 'BE')
  const index = concatBytes(numberToUint32(bucket, 'BE'), numberToUint32(slot, 'BE'))
  const timestamp = numberToUint64(BigInt(timestampMs) * 1_000_000n, 'BE') // Bee uses unix nanoseconds

  const signature = privateKey.sign(concatBytes(address, batch.toUint8Array(), index, timestamp))

  return {
    batchId: batch,
    index,
    issuer: privateKey.publicKey().address(),
    signature,
    timestamp,
  }
}

/**
 * Stateful postage stamp issuer: tracks how many chunks have been stamped
 * into each of the batch's 65536 buckets, so each chunk gets a distinct,
 * capacity-respecting index without the caller managing that bookkeeping.
 */
export class Stamper {
  signer: PrivateKey
  batchId: BatchId
  buckets: Uint32Array
  depth: number
  maxSlot: number

  private constructor(signer: PrivateKey, batchId: BatchId, buckets: Uint32Array, depth: number) {
    this.signer = signer
    this.batchId = batchId
    this.buckets = buckets
    this.depth = depth
    this.maxSlot = 2 ** (depth - 16)
  }

  /**
   * Creates a fresh Stamper for a batch with no chunks stamped yet.
   */
  static fromBlank(
    signer: PrivateKey | Uint8Array | string,
    batchId: BatchId | Uint8Array | string,
    depth: number,
  ): Stamper {
    return new Stamper(new PrivateKey(signer), new BatchId(batchId), new Uint32Array(65536), depth)
  }

  /**
   * Resumes a Stamper from a previously persisted bucket state (see {@link getState}).
   */
  static fromState(
    signer: PrivateKey | Uint8Array | string,
    batchId: BatchId | Uint8Array | string,
    buckets: Uint32Array,
    depth: number,
  ): Stamper {
    return new Stamper(new PrivateKey(signer), new BatchId(batchId), buckets, depth)
  }

  /**
   * Stamps a chunk address, automatically picking and reserving the next
   * free slot in its bucket. Throws once a bucket reaches its depth-derived capacity.
   */
  stamp(address: Uint8Array, timestampMs?: number): EnvelopeWithBatchId {
    const bucket = uint16ToNumber(address, 'BE')
    const height = this.buckets[bucket]!

    if (height >= this.maxSlot) {
      throw new Error('Stamper#stamp bucket is full')
    }

    this.buckets[bucket] = height + 1

    return stamp(this.signer, this.batchId, address, height, timestampMs)
  }

  /**
   * Returns the live bucket-height state, for persisting and later resuming
   * via {@link fromState}.
   */
  getState(): Uint32Array {
    return this.buckets
  }
}
