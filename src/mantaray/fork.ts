import { commonPrefix, numberToUint16, numberToUint8, uint16ToNumber, uint8ToNumber } from '../bytes/encoding.js'
import { Uint8ArrayReader } from '../chunk/byte-cursor.js'
import { MantarayNode } from './node.js'
import { Bytes } from '../bytes/bytes.js'

const TYPE_WITH_METADATA = 16

const ENCODER = new TextEncoder()
const DECODER = new TextDecoder()

function isType(value: number, type: number): boolean {
  return (value & type) === type
}

function padEndToMultiple(bytes: Uint8Array, multiple: number, paddingByte: number): Uint8Array {
  const remainder = bytes.length % multiple
  if (remainder === 0) {
    return bytes
  }
  const result = new Uint8Array(bytes.length + multiple - remainder).fill(paddingByte)
  result.set(bytes, 0)

  return result
}

/**
 * A single edge in a MantarayNode's trie: the shared path `prefix` leading
 * to `node`. Forks are keyed by their prefix's first byte in the parent's
 * `forks` map.
 */
export class Fork {
  prefix: Uint8Array
  node: MantarayNode

  constructor(prefix: Uint8Array, node: MantarayNode) {
    this.prefix = prefix
    this.node = node
  }

  /**
   * Merges two forks that share a path prefix, splitting off a new
   * intermediate node at the point where their prefixes diverge.
   */
  static split(a: Fork, b: Fork): Fork {
    const commonPart = commonPrefix(a.prefix, b.prefix)

    if (commonPart.length === a.prefix.length) {
      const remainingB = b.prefix.slice(commonPart.length)
      b.node.path = b.prefix.slice(commonPart.length)
      b.prefix = b.prefix.slice(commonPart.length)
      b.node.parent = a.node
      a.node.forks.set(remainingB[0]!, b)

      return a
    }

    if (commonPart.length === b.prefix.length) {
      const remainingA = a.prefix.slice(commonPart.length)
      a.node.path = a.prefix.slice(commonPart.length)
      a.prefix = a.prefix.slice(commonPart.length)
      a.node.parent = b.node
      b.node.forks.set(remainingA[0]!, a)

      return b
    }

    const node = new MantarayNode({ path: commonPart, encrypt: a.node.encrypt })

    const newAFork = new Fork(a.prefix.slice(commonPart.length), a.node)
    const newBFork = new Fork(b.prefix.slice(commonPart.length), b.node)

    a.node.path = a.prefix.slice(commonPart.length)
    b.node.path = b.prefix.slice(commonPart.length)
    a.prefix = a.prefix.slice(commonPart.length)
    b.prefix = b.prefix.slice(commonPart.length)

    node.forks.set(newAFork.prefix[0]!, newAFork)
    node.forks.set(newBFork.prefix[0]!, newBFork)

    newAFork.node.parent = node
    newBFork.node.parent = node

    return new Fork(commonPart, node)
  }

  /**
   * Gets the binary representation of the fork (type byte, prefix, self
   * address, and optional metadata).
   */
  marshal(): Uint8Array {
    if (!this.node.selfAddress) {
      throw new Error('Fork#marshal node.selfAddress is not set')
    }
    const data: Uint8Array[] = []
    // Re-emit the type byte read from the chunk when the node is untouched, so an
    // unmarshal -> marshal round-trip is byte-identical. determineType() can only
    // recompute it correctly once the node's children are loaded/built in memory.
    data.push(new Uint8Array([this.node.type ?? this.node.determineType()]))
    data.push(numberToUint8(this.prefix.length))
    data.push(this.prefix)

    if (this.prefix.length < 30) {
      data.push(new Uint8Array(30 - this.prefix.length))
    }
    data.push(this.node.selfAddress)

    if (this.node.metadata) {
      const metadataBytes = padEndToMultiple(
        Bytes.concat(new Uint8Array([0x00, 0x00]), ENCODER.encode(JSON.stringify(this.node.metadata))),
        32,
        0x0a,
      )
      metadataBytes.set(numberToUint16(metadataBytes.length - 2, 'BE'), 0)
      data.push(metadataBytes)
    }

    return Bytes.concat(...data)
  }

  /**
   * Reads a single fork (and its node's selfAddress/metadata) out of a
   * reader positioned at the start of the fork's bytes.
   */
  static unmarshal(reader: Uint8ArrayReader, addressLength: number): Fork {
    const type = uint8ToNumber(reader.read(1))
    const prefixLength = uint8ToNumber(reader.read(1))
    const prefix = reader.read(prefixLength)

    if (prefixLength < 30) {
      reader.read(30 - prefixLength)
    }
    const selfAddress = reader.read(addressLength)
    let metadata: Record<string, string> | undefined = undefined

    if (isType(type, TYPE_WITH_METADATA)) {
      const metadataLength = uint16ToNumber(reader.read(2), 'BE')

      if (metadataLength > reader.max()) {
        throw new Error('Fork#unmarshal not enough bytes for metadata')
      }
      metadata = JSON.parse(DECODER.decode(reader.read(metadataLength)))
    }

    return new Fork(prefix, new MantarayNode({ selfAddress, metadata, path: prefix, type }))
  }
}
