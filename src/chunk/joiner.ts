import { uint64ToNumber } from '../bytes/encoding.js'
import { decryptChunk } from '../encryption/stream-cipher.js'
import { decodeRedundancyLevel, referenceCount } from '../erasure-coding/span.js'
import { Bytes } from '../bytes/bytes.js'

function isAllZero(bytes: Uint8Array): boolean {
  for (let i = 0; i < bytes.length; i++) {
    if (bytes[i] !== 0) return false
  }

  return true
}

/**
 * Reconstructs the original data behind a chunk tree (as produced by
 * ChunkSplitter), fetching chunks on demand via a caller-supplied callback.
 */
export class ChunkJoiner {
  private refSize: number
  private encrypted: boolean
  private fetch: (address: Uint8Array) => Promise<Uint8Array>
  private onData: (data: Uint8Array) => Promise<void>

  constructor(
    fetch: (address: Uint8Array) => Promise<Uint8Array>,
    onData: (data: Uint8Array) => Promise<void>,
    encrypted = false,
  ) {
    this.fetch = fetch
    this.onData = onData
    this.encrypted = encrypted
    this.refSize = encrypted ? 64 : 32
  }

  /**
   * Fetches and reconstructs the full data behind an unencrypted chunk tree.
   */
  static async collect(address: Uint8Array, fetch: (address: Uint8Array) => Promise<Uint8Array>): Promise<Uint8Array> {
    const parts: Uint8Array[] = []
    await new ChunkJoiner(fetch, async data => {
      parts.push(data)
    }).join(address)

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
  ): Promise<Uint8Array> {
    const parts: Uint8Array[] = []
    await new ChunkJoiner(
      fetch,
      async data => {
        parts.push(data)
      },
      true,
    ).join(address, key)

    return Bytes.concat(...parts)
  }

  /**
   * Fetches the chunk at `address` and recursively descends into its
   * children (skipping any parity references), emitting leaf payloads to
   * `onData` in order as they're reached.
   */
  async join(address: Uint8Array, key?: Uint8Array): Promise<void> {
    const raw = await this.fetch(address)
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

    const maxRefs = Math.floor(4096 / this.refSize)
    // Without redundancy there's no way to tell real children from padding
    // apart from the all-zero terminator. With redundancy, the data/parity
    // split is computed from the span instead - parity refs are appended
    // right after the data refs with no marker of their own, and must be
    // skipped rather than descended into.
    const dataRefCount = level > 0 ? referenceCount(span, level, this.encrypted).dataShardCount : maxRefs

    for (let i = 0; i < Math.min(dataRefCount, maxRefs); i++) {
      const ref = data.subarray(i * this.refSize, (i + 1) * this.refSize)
      const childAddress = ref.subarray(0, 32)
      if (level === 0 && isAllZero(childAddress)) break
      await this.join(childAddress, this.encrypted ? ref.subarray(32, 64) : undefined)
    }
  }
}
