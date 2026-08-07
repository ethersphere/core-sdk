import {
  commonPrefix,
  concatBytes,
  equals,
  hexToUint8Array,
  indexOf,
  numberToUint8,
  uint8ToNumber,
} from '../bytes/encoding.js'
import { Reference } from '../bytes/reference.js'
import { Uint8ArrayReader } from '../chunk/byte-cursor.js'
import { ChunkBuilder, ChunkEntry, ChunkSplitter } from '../chunk/splitter.js'
import { xorCypher } from '../encryption/xor-cipher.js'
import { Fork } from './fork.js'

const ENCODER = new TextEncoder()
const DECODER = new TextDecoder()

const TYPE_VALUE = 2
const TYPE_EDGE = 4
const TYPE_WITH_PATH_SEPARATOR = 8
const TYPE_WITH_METADATA = 16
const PATH_SEPARATOR = new Uint8Array([47])
const VERSION_02_HASH = hexToUint8Array('5768b3b6a7db56d21d1abff40d41cebfc83448fed8d7e9b06ec0d3b073f28f7b')

// Mantaray's per-node fork bitmap is always bit-indexed little-endian - the
// only order either source implementation ever uses, so it's hardcoded here
// rather than threaded through as a parameter.
function setBit(bytes: Uint8Array, index: number): void {
  const byteIndex = Math.floor(index / 8)
  const bitIndex = index % 8
  bytes[byteIndex] = bytes[byteIndex]! | (1 << bitIndex)
}

function getBit(bytes: Uint8Array, index: number): boolean {
  const byteIndex = Math.floor(index / 8)
  const bitIndex = index % 8

  return ((bytes[byteIndex]! >> bitIndex) & 0x01) === 1
}

interface MantarayNodeOptions {
  selfAddress?: Uint8Array | undefined
  targetAddress?: Uint8Array | undefined
  obfuscationKey?: Uint8Array
  metadata?: Record<string, string> | null | undefined
  path?: Uint8Array | null
  parent?: MantarayNode | null
  type?: number | null
  encrypt?: boolean
}

/**
 * A node in Swarm's Mantaray trie - the data structure backing manifests
 * (directory listings, website hosting, feed pointers). Each node holds an
 * optional target address (the value at this path) and a set of forks -
 * single-byte-keyed edges to child nodes, each carrying a shared path prefix.
 */
export class MantarayNode {
  public obfuscationKey: Uint8Array = new Uint8Array(32)
  public selfAddress: Uint8Array | null = null
  public targetAddress: Uint8Array = new Uint8Array(32)
  public metadata: Record<string, string> | undefined | null = null
  public path: Uint8Array = new Uint8Array(0)
  public forks: Map<number, Fork> = new Map()
  public parent: MantarayNode | null = null
  public type: number | null = null
  public encrypt: boolean = false

  constructor(options?: MantarayNodeOptions) {
    if (options?.encrypt) {
      this.encrypt = true
    }

    if (options?.targetAddress) {
      this.targetAddress = options.targetAddress
    } else if (this.encrypt) {
      this.targetAddress = new Uint8Array(64)
    }

    if (options?.selfAddress) {
      this.selfAddress = options.selfAddress
    }

    if (options?.metadata) {
      this.metadata = options.metadata
    }

    if (options?.obfuscationKey) {
      this.obfuscationKey = options.obfuscationKey
    }

    if (options?.path) {
      this.path = options.path
    }

    if (options?.parent) {
      this.parent = options.parent
    }

    this.type = options?.type ?? null
  }

  /**
   * The full path from the tree's root to this node, concatenating every
   * ancestor's own path segment.
   */
  get fullPath(): Uint8Array {
    return concatBytes(this.parent?.fullPath ?? new Uint8Array(0), this.path)
  }

  /**
   * {@link fullPath} decoded as UTF-8.
   */
  get fullPathString(): string {
    return DECODER.decode(this.fullPath)
  }

  /**
   * Gets the binary representation of the node.
   */
  async marshal(): Promise<Uint8Array> {
    for (const fork of this.forks.values()) {
      if (!fork.node.selfAddress) {
        fork.node.selfAddress = (await fork.node.calculateSelfAddress()).toUint8Array()
      }
    }

    if (this.encrypt && equals(this.obfuscationKey, new Uint8Array(32))) {
      this.obfuscationKey = new Uint8Array(32)
      crypto.getRandomValues(this.obfuscationKey)
    }

    // A null (all-zero) targetAddress means this node has no entry of its
    // own (e.g. a metadata-only "/" node). Bee (Go) then writes a 0-byte
    // entry, inferring refBytesSize from a fork's reference width when one
    // exists, rather than padding the entry out to the default 32/64 bytes -
    // matching that here keeps hashes identical to a real Bee-produced
    // manifest for the same content.
    const hasEntry = !equals(this.targetAddress, new Uint8Array(this.targetAddress.length))
    let refBytesSize = 0

    if (hasEntry) {
      refBytesSize = this.targetAddress.length
    } else {
      for (const fork of this.forks.values()) {
        if (fork.node.selfAddress && fork.node.selfAddress.length > 0) {
          refBytesSize = fork.node.selfAddress.length
          break
        }
      }
    }

    const header = new Uint8Array(32)
    header.set(VERSION_02_HASH, 0)
    header.set(numberToUint8(refBytesSize), 31)
    const entry = hasEntry ? this.targetAddress : new Uint8Array(refBytesSize)

    const forkBitmap = new Uint8Array(32)
    for (const fork of this.forks.keys()) {
      setBit(forkBitmap, fork)
    }

    const forks: Uint8Array[] = []
    for (let i = 0; i < 256; i++) {
      if (getBit(forkBitmap, i)) {
        forks.push(this.forks.get(i)!.marshal())
      }
    }

    const data = xorCypher(concatBytes(header, entry, forkBitmap, ...forks), this.obfuscationKey)

    return concatBytes(this.obfuscationKey, data)
  }

  /**
   * Unmarshals a MantarayNode from previously marshaled data. Each fork's
   * child node only carries its own `selfAddress` - fetch and unmarshal it
   * (e.g. via `saveRecursively`'s chunk store) to descend further.
   */
  static unmarshalFromData(data: Uint8Array, selfAddress?: Uint8Array): MantarayNode {
    if (data.length < 64) {
      throw new Error('MantarayNode#unmarshalFromData data too short')
    }

    const obfuscationKey = data.subarray(0, 32)
    const decrypted = xorCypher(data.subarray(32), obfuscationKey)
    const reader = new Uint8ArrayReader(decrypted)
    const versionHash = reader.read(31)

    if (!equals(versionHash, VERSION_02_HASH.slice(0, 31))) {
      throw new Error('MantarayNode#unmarshalFromData invalid version hash')
    }

    const refBytesSize = uint8ToNumber(reader.read(1))

    const targetAddress = reader.read(refBytesSize)
    const node = new MantarayNode({ selfAddress, targetAddress, obfuscationKey })
    const forkBitmap = reader.read(32)

    // Older Bee nodes could persist a node with refBytesSize=0 despite its
    // forks still being marshaled at the standard 32-byte width - each fork's
    // width in Bee (Go) comes from that fork's own reference length, not from
    // the parent node's (possibly unset) refBytesSize. Falling back to 32
    // here recovers those forks; treating 0 as "no forks" would silently
    // drop real reference data, same as the bug fixed for marshal() itself.
    const forkRefSize = refBytesSize === 0 ? 32 : refBytesSize

    for (let i = 0; i < 256; i++) {
      if (getBit(forkBitmap, i)) {
        const fork = Fork.unmarshal(reader, forkRefSize)
        node.forks.set(i, fork)
        fork.node.parent = node
      }
    }

    return node
  }

  /**
   * Adds a fork to the node.
   */
  addFork(
    path: string | Uint8Array,
    reference: Reference | Uint8Array | string,
    metadata?: Record<string, string> | null,
  ): void {
    this.selfAddress = null
    this.type = null
    path = path instanceof Uint8Array ? path : ENCODER.encode(path)
    let tip: MantarayNode = this

    while (path.length) {
      const prefix = path.slice(0, 30)
      path = path.slice(30)
      const isLast = path.length === 0

      const [bestMatch, matchedPath] = tip.findClosest(prefix)
      const remainingPath = prefix.slice(matchedPath.length)

      if (matchedPath.length) {
        tip = bestMatch
      }

      if (!remainingPath.length) {
        continue
      }

      const newFork = new Fork(
        remainingPath,
        new MantarayNode({
          targetAddress: isLast ? new Reference(reference).toUint8Array() : undefined,
          metadata: isLast ? metadata : undefined,
          path: remainingPath,
          encrypt: this.encrypt,
        }),
      )

      const existing = bestMatch.forks.get(remainingPath[0]!)

      if (existing) {
        const fork = Fork.split(newFork, existing)
        tip.forks.set(remainingPath[0]!, fork)
        fork.node.parent = tip
      } else {
        tip.forks.set(remainingPath[0]!, newFork)
        newFork.node.parent = tip
      }

      tip.selfAddress = null
      tip.type = null
      tip = newFork.node
    }
  }

  /**
   * Removes a fork from the node.
   */
  removeFork(path: string | Uint8Array): void {
    this.selfAddress = null
    this.type = null
    path = path instanceof Uint8Array ? path : ENCODER.encode(path)

    if (path.length === 0) {
      throw new Error('MantarayNode#removeFork path cannot be empty')
    }

    const match = this.find(path)

    if (!match) {
      throw new Error('MantarayNode#removeFork fork not found')
    }

    const [parent, matchedPath] = this.findClosest(path.slice(0, path.length - 1))
    parent.forks.delete(path.slice(matchedPath.length)[0]!)

    for (const fork of match.forks.values()) {
      parent.addFork(concatBytes(match.path, fork.prefix), fork.node.targetAddress, fork.node.metadata)
    }
  }

  /**
   * Calculates the self address of the node.
   */
  async calculateSelfAddress(): Promise<Reference> {
    if (this.selfAddress) {
      return new Reference(this.selfAddress)
    }

    if (this.encrypt) {
      throw new Error('MantarayNode#calculateSelfAddress is not supported for encrypted nodes - use saveRecursively')
    }

    return (await ChunkSplitter.root(await this.marshal())).hash()
  }

  /**
   * Saves the node and its children recursively via the given `onChunk`
   * callback - no network client involved, the caller decides how and where
   * chunks get persisted.
   *
   * Returns the reference to the saved manifest (32 bytes, or 64 bytes -
   * address || key - for an encrypted manifest) and the root chunk, so
   * callers can also create dispersed replicas from it.
   */
  async saveRecursively(
    onChunk: (chunk: ChunkBuilder, key?: Uint8Array) => Promise<void>,
  ): Promise<{ reference: Uint8Array; rootChunk: ChunkBuilder; encryptionKey?: Uint8Array }> {
    for (const fork of this.forks.values()) {
      await fork.node.saveRecursively(onChunk)
    }

    const onBatch = async (batch: ChunkEntry[]): Promise<ChunkEntry[]> => {
      for (const { chunk, key } of batch) {
        await onChunk(chunk, key)
      }

      return []
    }

    const splitter = new ChunkSplitter(onBatch, undefined, this.encrypt)
    await splitter.append(await this.marshal())
    const rootChunk = await splitter.finalize()

    if (this.encrypt) {
      const { address, key } = rootChunk.encryptedHash()
      await onChunk(rootChunk, key)
      this.selfAddress = concatBytes(address.toUint8Array(), key)

      return { reference: this.selfAddress, rootChunk, encryptionKey: key }
    }

    await onChunk(rootChunk)
    this.selfAddress = rootChunk.hash().toUint8Array()

    return { reference: this.selfAddress, rootChunk }
  }

  /**
   * Finds a node in the tree by its path.
   */
  find(path: string | Uint8Array): MantarayNode | null {
    const target = path instanceof Uint8Array ? path : ENCODER.encode(path)
    const [closest, matched] = this.findClosest(target)

    return matched.length === target.length ? closest : null
  }

  /**
   * Finds the closest node in the tree to the given path.
   */
  findClosest(path: string | Uint8Array, current: Uint8Array = new Uint8Array()): [MantarayNode, Uint8Array] {
    path = path instanceof Uint8Array ? path : ENCODER.encode(path)

    if (path.length === 0) {
      return [this, current]
    }

    const fork = this.forks.get(path[0]!)

    if (fork && commonPrefix(fork.prefix, path).length === fork.prefix.length) {
      return fork.node.findClosest(path.slice(fork.prefix.length), concatBytes(current, fork.prefix))
    }

    return [this, current]
  }

  /**
   * Returns every node in the tree that has a target address set.
   */
  collect(nodes: MantarayNode[] = []): MantarayNode[] {
    for (const fork of this.forks.values()) {
      if (!equals(fork.node.targetAddress, new Uint8Array(fork.node.targetAddress.length))) {
        nodes.push(fork.node)
      }
      fork.node.collect(nodes)
    }

    return nodes
  }

  /**
   * Returns a path -> reference (hex) map of every node in the tree that has
   * a target address set.
   */
  collectAndMap(): Record<string, string> {
    const result: Record<string, string> = {}

    for (const node of this.collect()) {
      result[node.fullPathString] = new Reference(node.targetAddress).toHex()
    }

    return result
  }

  /**
   * Computes this node's type byte (value/edge/path-separator/metadata
   * flags) from its current in-memory state.
   */
  determineType(): number {
    let type = 0
    const nullAddress = new Uint8Array(this.targetAddress.length)

    // Mirrors Bee (pkg/manifest/mantaray/node.go): a leaf (no forks) is always
    // a value, even with a null entry (e.g. a metadata-only "/" node); a node
    // with forks is a value only when it also carries an entry. Verified
    // against a real Bee-produced marshal/unmarshal round-trip in
    // test/mantaray.test.ts.
    if (!equals(this.targetAddress, nullAddress) || this.forks.size === 0) {
      type |= TYPE_VALUE
    }

    if (this.forks.size > 0) {
      type |= TYPE_EDGE
    }

    if (indexOf(this.path, PATH_SEPARATOR) > 0) {
      type |= TYPE_WITH_PATH_SEPARATOR
    }

    if (this.metadata) {
      type |= TYPE_WITH_METADATA
    }

    return type
  }
}
