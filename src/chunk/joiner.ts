import { uint64ToNumber } from '../bytes/encoding.js'
import { decryptChunk } from '../encryption/stream-cipher.js'
import { decodeRedundancyLevel, referenceCount } from '../erasure-coding/span.js'
import { Bytes } from '../bytes/bytes.js'
import { Reference } from '../bytes/reference.js'
import { verifyFetchedChunk } from './verify.js'

const ENCRYPTED_REFERENCE_LENGTH = Reference.LENGTH * 2

export interface ChunkJoinerOptions {
  verify?: boolean
}

/**
 * Reconstructs the original data behind a chunk tree (as produced by
 * ChunkSplitter), fetching chunks on demand via a caller-supplied callback.
 */
export class ChunkJoiner {
  private refSize: number
  private encrypted: boolean
  private verify: boolean
  private fetch: (address: Uint8Array) => Promise<Uint8Array>
  private onData: (data: Uint8Array) => Promise<void>

  constructor(
    fetch: (address: Uint8Array) => Promise<Uint8Array>,
    onData: (data: Uint8Array) => Promise<void>,
    encrypted = false,
    verify = false,
  ) {
    this.fetch = fetch
    this.onData = onData
    this.encrypted = encrypted
    this.verify = verify
    this.refSize = encrypted ? 64 : 32
  }

  /**
   * Fetches and reconstructs the full data behind a reference, decrypting it when the reference is 64 bytes.
   */
  static collect(
    reference: Reference | string,
    fetch: (address: Reference) => Promise<Uint8Array>,
    options?: ChunkJoinerOptions,
  ): Promise<Uint8Array>
  /**
   * Fetches and reconstructs the full data behind an unencrypted chunk tree.
   */
  static collect(
    address: Uint8Array,
    fetch: (address: Uint8Array) => Promise<Uint8Array>,
    options?: ChunkJoinerOptions,
  ): Promise<Uint8Array>
  static async collect(
    address: Reference | string | Uint8Array,
    fetch: ((address: Reference) => Promise<Uint8Array>) | ((address: Uint8Array) => Promise<Uint8Array>),
    options: ChunkJoinerOptions = {},
  ): Promise<Uint8Array> {
    if (address instanceof Uint8Array) {
      return ChunkJoiner.collectPlain(address, fetch as (address: Uint8Array) => Promise<Uint8Array>, options)
    }

    const reference = new Reference(address).toUint8Array()
    const fetchByReference = (chunkAddress: Uint8Array) =>
      (fetch as (address: Reference) => Promise<Uint8Array>)(new Reference(chunkAddress))

    if (reference.length === ENCRYPTED_REFERENCE_LENGTH) {
      return ChunkJoiner.collectEncrypted(
        reference.subarray(0, Reference.LENGTH),
        reference.subarray(Reference.LENGTH),
        fetchByReference,
        options,
      )
    }

    return ChunkJoiner.collectPlain(reference, fetchByReference, options)
  }

  private static async collectPlain(
    address: Uint8Array,
    fetch: (address: Uint8Array) => Promise<Uint8Array>,
    options: ChunkJoinerOptions,
  ): Promise<Uint8Array> {
    const parts: Uint8Array[] = []
    await new ChunkJoiner(
      fetch,
      async data => {
        parts.push(data)
      },
      false,
      options.verify,
    ).join(address)

    return Bytes.concat(...parts)
  }

  /**
   * Fetches and reconstructs the full data behind an encrypted chunk tree,
   * given the root's decryption key.
   */
  static async collectEncrypted(
    address: Uint8Array,
    key: Uint8Array,
    fetch: (address: Uint8Array) => Promise<Uint8Array>,
    options: ChunkJoinerOptions = {},
  ): Promise<Uint8Array> {
    const parts: Uint8Array[] = []
    await new ChunkJoiner(
      fetch,
      async data => {
        parts.push(data)
      },
      true,
      options.verify,
    ).join(address, key)

    return Bytes.concat(...parts)
  }

  /**
   * Fetches the chunk at `address` and recursively descends into its
   * children (skipping any parity references), emitting leaf payloads to
   * `onData` in order as they're reached.
   */
  async join(address: Uint8Array, key?: Uint8Array): Promise<void> {
    const fetched = await this.fetch(address)
    const raw = this.verify ? verifyFetchedChunk(address, fetched) : fetched
    let rawSpan: bigint
    let data: Uint8Array
    if (this.encrypted && key) {
      ;({ span: rawSpan, data } = decryptChunk(raw, key))
    } else {
      rawSpan = uint64ToNumber(raw.subarray(0, 8), 'LE')
      data = raw.subarray(8, 4104)
    }

    const { level, span } = decodeRedundancyLevel(rawSpan)

    if (span <= 4096n) {
      await this.onData(data.subarray(0, Number(span)))
      return
    }

    const { dataShardCount } = referenceCount(span, level, this.encrypted)

    for (let i = 0; i < dataShardCount; i++) {
      const ref = data.subarray(i * this.refSize, (i + 1) * this.refSize)
      const childAddress = ref.subarray(0, 32)
      await this.join(childAddress, this.encrypted ? ref.subarray(32, 64) : undefined)
    }
  }
}
