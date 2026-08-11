import { numberToUint64 } from '../bytes/encoding.js'
import { Reference } from '../bytes/reference.js'
import { encryptData, encryptSpan } from '../encryption/stream-cipher.js'
import { calculateChunkAddress } from './bmt.js'
import { Uint8ArrayReader, Uint8ArrayWriter } from './byte-cursor.js'
import { Bytes } from '../bytes/bytes.js'

// Named ChunkBuilder (not Chunk) to avoid colliding with the immutable CAC
// `Chunk` shape in chunk/cac.ts - this is a different, mutable thing: a
// 4096-byte buffer being filled in over time, before it's ever hashed.
/**
 * A chunk (up to 4096 bytes of payload) being filled in by a ChunkSplitter,
 * before it's sealed. Unlike the immutable CAC {@link Chunk}, this is a
 * mutable buffer - only `hash()`/`encryptedHash()`/`build()` finalize it.
 */
export class ChunkBuilder {
  span: bigint
  writer: Uint8ArrayWriter

  constructor(span = 0n) {
    this.span = span
    this.writer = new Uint8ArrayWriter(new Uint8Array(4096))
  }

  /**
   * Returns the raw chunk bytes: 8-byte span || 4096-byte payload buffer.
   */
  build(): Uint8Array {
    return Bytes.concat(numberToUint64(this.span, 'LE'), this.writer.buffer)
  }

  /**
   * Computes the unencrypted BMT address of this chunk.
   */
  hash(): Reference {
    return calculateChunkAddress(this.build())
  }

  /**
   * Encrypts this chunk with `key` (generating a random one if omitted) and
   * returns the resulting address alongside the key used.
   */
  encryptedHash(key?: Uint8Array): { address: Reference; key: Uint8Array } {
    if (!key) {
      key = new Uint8Array(32)
      crypto.getRandomValues(key)
    }
    const encSpan = encryptSpan(key, numberToUint64(this.span, 'LE'))
    const encPayload = encryptData(key, this.writer.buffer)

    return { address: calculateChunkAddress(Bytes.concat(encSpan, encPayload)), key }
  }
}

/** A sealed chunk awaiting upload, with its encryption key if encrypted. */
export type ChunkEntry = { chunk: ChunkBuilder; key?: Uint8Array }

type PendingEntry = { entry: ChunkEntry; ref: Uint8Array; span: bigint }

/**
 * Splits arbitrary data into a tree of 4096-byte chunks (the inverse of
 * ChunkJoiner), calling `onBatch` with each level's sealed chunks as they
 * fill up - e.g. to upload them, or (via erasure-coding/batch.ts) to add
 * Reed-Solomon parity chunks.
 */
export class ChunkSplitter {
  static readonly NOOP = async (_: ChunkEntry[]) => [] as ChunkEntry[]

  private refSize: number
  private encrypted: boolean
  private maxShards: number
  private chunks: ChunkBuilder[]
  private counters: number[] = [1]
  private pending: PendingEntry[][] = [[]]
  private onBatch: (batch: ChunkEntry[]) => Promise<ChunkEntry[]>
  private onIntermediateChunk?: ((chunk: ChunkBuilder, hasParity: boolean) => void) | undefined
  private hasParity: boolean[] = [false]
  private pendingEntries: ChunkEntry[][] = []

  /**
   * @param onBatch Called with each level's sealed chunks as a batch fills
   * up; return any parity entries to append as extra references (empty
   * array for no redundancy).
   * @param maxShards Max data-chunk references per intermediate node.
   * Defaults to as many as fit in one 4096-byte node; pass a smaller value
   * (e.g. via erasure-coding's getMaxShards) to leave room for parity refs.
   * @param onIntermediateChunk Called with each intermediate chunk as it's
   * sealed, so callers can tag it (e.g. encoding a redundancy level into its span).
   */
  constructor(
    onBatch: (batch: ChunkEntry[]) => Promise<ChunkEntry[]>,
    maxShards?: number,
    encrypted = false,
    onIntermediateChunk?: (chunk: ChunkBuilder, hasParity: boolean) => void,
  ) {
    this.encrypted = encrypted
    this.refSize = encrypted ? 64 : 32
    this.maxShards = maxShards ?? 4096 / this.refSize
    this.chunks = [new ChunkBuilder()]
    this.onBatch = onBatch
    this.onIntermediateChunk = onIntermediateChunk
  }

  /**
   * Splits `data` into a chunk tree (no redundancy, no encryption, no
   * upload callback) and returns just its root chunk.
   */
  static async root(data: Uint8Array): Promise<ChunkBuilder> {
    const tree = new ChunkSplitter(ChunkSplitter.NOOP)
    await tree.append(data)

    return tree.finalize()
  }

  /**
   * Splits `data` into an encrypted chunk tree (no upload callback) and
   * returns the root's encrypted address and key.
   */
  static async encryptedRoot(data: Uint8Array): Promise<{ address: Reference; key: Uint8Array }> {
    const tree = new ChunkSplitter(ChunkSplitter.NOOP, undefined, true)
    await tree.append(data)
    const root = await tree.finalize()

    return root.encryptedHash()
  }

  /**
   * Appends more data to the tree, sealing and elevating chunks as needed.
   * `level`/`spanIncrement` are internal - callers building a tree from raw
   * input data should always call this at the default level 0.
   */
  async append(data: Uint8Array, level = 0, spanIncrement = 0n): Promise<void> {
    const reader = new Uint8ArrayReader(data)
    while (reader.max() > 0) {
      if (this.chunks[level]!.writer.max() === 0 || (spanIncrement && this.chunks[level]!.writer.max() < data.length)) {
        await this.elevate(level)
      }
      const written = this.chunks[level]!.writer.write(reader)
      if (spanIncrement) {
        this.chunks[level]!.span += spanIncrement
      } else {
        this.chunks[0]!.span += BigInt(written)
      }
    }
  }

  private async elevate(level: number): Promise<void> {
    this.counters[level] = (this.counters[level]! + 1) % (4096 / this.refSize)
    if (!this.pending[level]) this.pending[level] = []

    await this.sealParities(level)

    const originalSpan = this.chunks[level]!.span

    if (level >= 1 && this.onIntermediateChunk) {
      this.onIntermediateChunk(this.chunks[level]!, this.hasParity[level] ?? false)
      this.hasParity[level] = false
    }

    if (this.encrypted) {
      const { address, key } = this.chunks[level]!.encryptedHash()
      const ref = new Uint8Array(64)
      ref.set(address.toUint8Array())
      ref.set(key, 32)
      this.pending[level]!.push({ entry: { chunk: this.chunks[level]!, key }, ref, span: originalSpan })
    } else {
      this.pending[level]!.push({
        entry: { chunk: this.chunks[level]! },
        ref: this.chunks[level]!.hash().toUint8Array(),
        span: originalSpan,
      })
    }
    this.chunks[level] = new ChunkBuilder()

    if (this.pending[level]!.length >= this.maxShards) {
      await this.flushBatch(level)
    }
  }

  private async sealParities(level: number): Promise<void> {
    const entries = this.pendingEntries[level]
    if (!entries?.length) return
    this.pendingEntries[level] = []
    const parities = await this.onBatch(entries)
    if (parities.length > 0) {
      this.hasParity[level] = true
      for (const { chunk } of parities) {
        this.chunks[level]!.writer.write(new Uint8ArrayReader(chunk.hash().toUint8Array()))
      }
    }
  }

  private async flushBatch(level: number): Promise<void> {
    if (!this.chunks[level + 1]) {
      this.chunks.push(new ChunkBuilder())
      this.counters.push(1)
      this.pending.push([])
      this.hasParity.push(false)
    }
    const batch = this.pending[level]!
    this.pending[level] = []

    for (const { ref, span } of batch) {
      await this.append(ref, level + 1, span)
    }

    if (!this.pendingEntries[level + 1]) this.pendingEntries[level + 1] = []
    this.pendingEntries[level + 1]!.push(...batch.map(p => p.entry))

    if (batch.length >= this.maxShards) await this.sealParities(level + 1)
  }

  /**
   * Seals every level and returns the tree's root chunk. `level` is
   * internal - callers should always start at the default level 0.
   */
  async finalize(level = 0): Promise<ChunkBuilder> {
    if (this.pending[level]?.length) {
      await this.flushBatch(level)
    }

    if (!this.chunks[level + 1]) {
      await this.sealParities(level)
      if (level >= 1 && this.onIntermediateChunk) {
        this.onIntermediateChunk(this.chunks[level]!, this.hasParity[level] ?? false)
      }

      return this.chunks[level]!
    }

    if (this.counters[level] === 1) {
      await this.elevate(level + 1)
      await this.flushBatch(level + 1)
      this.chunks[level + 1] = this.chunks[level]!

      return this.finalize(level + 1)
    }

    await this.elevate(level)
    await this.flushBatch(level)

    return this.finalize(level + 1)
  }
}
