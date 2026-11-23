import { Bytes } from '../bytes/bytes.js'
import { numberToUint64 } from '../bytes/encoding.js'
import { Reference } from '../bytes/reference.js'
import { encryptData, encryptSpan } from '../encryption/stream-cipher.js'
import { makeErasureBatch, makeIntermediateChunkHandler } from '../erasure-coding/batch.js'
import { getMaxShards } from '../erasure-coding/levels.js'
import { makeEncryptedReplicas, makeReplicas } from './soc.js'
import { ChunkBuilder, ChunkSplitter, unpaddedChunkData } from './splitter.js'

const MAX_REDUNDANCY_LEVEL = 4

export interface SplitChunk {
  address: Reference
  data: Uint8Array
}

export interface DataSplitterOptions {
  encrypted?: boolean
  redundancyLevel?: number
  onChunk: (chunk: SplitChunk) => Promise<void>
}

/**
 * Splits data into ready-to-upload chunks, including parity chunks, the root chunk and its replicas.
 */
export class DataSplitter {
  private readonly encrypted: boolean
  private readonly redundancyLevel: number
  private readonly onChunk: (chunk: SplitChunk) => Promise<void>
  private readonly splitter: ChunkSplitter
  private finalized = false

  constructor({ encrypted = false, redundancyLevel = 0, onChunk }: DataSplitterOptions) {
    if (!Number.isInteger(redundancyLevel) || redundancyLevel < 0 || redundancyLevel > MAX_REDUNDANCY_LEVEL) {
      throw new RangeError(`Redundancy level out of range: ${redundancyLevel}`)
    }

    this.encrypted = encrypted
    this.redundancyLevel = redundancyLevel
    this.onChunk = onChunk
    this.splitter = new ChunkSplitter(
      makeErasureBatch(redundancyLevel, encrypted, (chunk, key, address) => onChunk(toSplitChunk(chunk, key, address))),
      getMaxShards(redundancyLevel, encrypted),
      encrypted,
      makeIntermediateChunkHandler(redundancyLevel),
    )
  }

  static async split(data: Uint8Array, options: DataSplitterOptions): Promise<Reference> {
    const splitter = new DataSplitter(options)
    await splitter.append(data)

    return splitter.finalize()
  }

  async append(data: Uint8Array): Promise<void> {
    this.assertNotFinalized()
    await this.splitter.append(data)
  }

  async finalize(): Promise<Reference> {
    this.assertNotFinalized()
    this.finalized = true
    const root = await this.splitter.finalize()

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
      throw new Error('DataSplitter is already finalized')
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
