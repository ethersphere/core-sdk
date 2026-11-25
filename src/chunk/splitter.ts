import { Bytes } from '../bytes/bytes.js'
import { numberToUint64 } from '../bytes/encoding.js'
import { Reference } from '../bytes/reference.js'
import { encryptData, encryptSpan } from '../encryption/stream-cipher.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../erasure-coding/batch.js'
import { getMaxShards } from '../erasure-coding/levels.js'
import { ChunkBuilder, ChunkTreeBuilder, unpaddedChunkData } from './chunk-tree.js'
import { makeEncryptedReplicas, makeReplicas } from './soc.js'

const MAX_REDUNDANCY_LEVEL = 4

export interface SplitChunk {
  address: Reference
  data: Uint8Array
}

export interface ChunkSplitterOptions {
  encrypted?: boolean
  redundancyLevel?: number
  onChunk?: (chunk: SplitChunk) => Promise<void>
}

/**
 * Splits data into ready-to-upload chunks, including parity chunks, the root chunk and its replicas.
 */
export class ChunkSplitter {
  private readonly encrypted: boolean
  private readonly redundancyLevel: number
  private readonly onChunk: (chunk: SplitChunk) => Promise<void>
  private readonly tree: ChunkTreeBuilder
  private finalized = false

  constructor({ encrypted = false, redundancyLevel = 0, onChunk = async () => {} }: ChunkSplitterOptions = {}) {
    if (!Number.isInteger(redundancyLevel) || redundancyLevel < 0 || redundancyLevel > MAX_REDUNDANCY_LEVEL) {
      throw new RangeError(`Redundancy level out of range: ${redundancyLevel}`)
    }

    this.encrypted = encrypted
    this.redundancyLevel = redundancyLevel
    this.onChunk = onChunk
    this.tree = new ChunkTreeBuilder(
      makeErasureBatch(redundancyLevel, encrypted, (chunk, key, address) => onChunk(toSplitChunk(chunk, key, address))),
      getMaxShards(redundancyLevel, encrypted),
      encrypted,
      makeIntermediateChunkHandler(redundancyLevel),
    )
  }

  static async split(data: Uint8Array, options: ChunkSplitterOptions = {}): Promise<Reference> {
    const splitter = new ChunkSplitter(options)
    await splitter.append(data)

    return splitter.finalize()
  }

  /**
   * Returns the unencrypted root chunk of `data` without emitting any chunks.
   */
  static async root(data: Uint8Array): Promise<ChunkBuilder> {
    const tree = new ChunkTreeBuilder(ChunkTreeBuilder.NOOP)
    await tree.append(data)

    return tree.finalize()
  }

  /**
   * Returns the encrypted root address and key of `data` without emitting any chunks.
   */
  static async encryptedRoot(data: Uint8Array): Promise<{ address: Reference; key: Uint8Array }> {
    const tree = new ChunkTreeBuilder(ChunkTreeBuilder.NOOP, undefined, true)
    await tree.append(data)
    const root = await tree.finalize()

    return root.encryptedHash()
  }

  async append(data: Uint8Array): Promise<void> {
    this.assertNotFinalized()
    await this.tree.append(data)
  }

  async finalize(): Promise<Reference> {
    this.assertNotFinalized()
    this.finalized = true
    const root = await this.tree.finalize()

    return this.encrypted ? this.emitEncryptedRoot(root) : this.emitRoot(root)
  }

  private async emitRoot(root: ChunkBuilder): Promise<Reference> {
    const address = root.hash()
    await this.onChunk({ address, data: unpaddedChunkData(root) })
    await this.emitAll(makeReplicas(root, this.redundancyLevel))

    return address
  }

  private async emitEncryptedRoot(root: ChunkBuilder): Promise<Reference> {
    const { address, key } = root.encryptedHash()
    await this.onChunk({ address, data: encryptedChunkData(root, key) })
    await this.emitAll(makeEncryptedReplicas(root, key, this.redundancyLevel))

    return new Reference(Bytes.concat(address.toUint8Array(), key))
  }

  private async emitAll(chunks: SplitChunk[]): Promise<void> {
    for (const chunk of chunks) {
      await this.onChunk(chunk)
    }
  }

  private assertNotFinalized(): void {
    if (this.finalized) {
      throw new Error('ChunkSplitter is already finalized')
    }
  }
}

function toSplitChunk(chunk: ChunkBuilder, key?: Uint8Array, address?: Reference): SplitChunk {
  if (key) {
    return { address: address ?? chunk.encryptedHash(key).address, data: encryptedChunkData(chunk, key) }
  }

  return { address: address ?? chunk.hash(), data: unpaddedChunkData(chunk) }
}

function encryptedChunkData(chunk: ChunkBuilder, key: Uint8Array): Uint8Array {
  return Bytes.concat(encryptSpan(key, numberToUint64(chunk.span, 'LE')), encryptData(key, chunk.writer.buffer))
}
