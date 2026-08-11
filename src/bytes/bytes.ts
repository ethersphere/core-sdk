import { keccak256 } from '../crypto/keccak.js'
import { hexToUint8Array, uint8ArrayToBase32, uint8ArrayToBase64, uint8ArrayToHex } from './encoding.js'

const DECODER = new TextDecoder()
const ENCODER = new TextEncoder()

const HEX_PATTERN = /^(0x)?[0-9a-fA-F]*$/i

function hasToHexMethod(value: unknown): value is { toHex(): string } {
  return typeof value === 'object' && value !== null && typeof (value as { toHex?: unknown }).toHex === 'function'
}

/**
 * Base wrapper around a byte array, accepting a Uint8Array, ArrayBuffer, hex
 * string, or another Bytes instance, with an optional length check.
 */
export class Bytes {
  protected readonly bytes: Uint8Array
  public readonly length: number

  /**
   * @param byteLength If given, throws unless the resulting length matches
   * (or, for an array, is one of) the expected length(s).
   */
  constructor(bytes: Uint8Array | ArrayBuffer | string | Bytes, byteLength?: number | number[]) {
    if (!bytes) {
      throw new Error(`Bytes#constructor: constructor parameter is falsy: ${bytes}`)
    }

    if (bytes instanceof Bytes) {
      this.bytes = bytes.bytes
    } else if (typeof bytes === 'string') {
      if (!HEX_PATTERN.test(bytes) || bytes.replace(/^0x/i, '').length % 2 !== 0) {
        throw new Error(`Bytes#constructor: invalid hex string: ${bytes}`)
      }
      this.bytes = hexToUint8Array(bytes)
    } else if (bytes instanceof ArrayBuffer) {
      this.bytes = new Uint8Array(bytes)
    } else if (bytes instanceof Uint8Array) {
      this.bytes = bytes
    } else {
      const unknownInput = bytes as unknown
      if (hasToHexMethod(unknownInput)) {
        this.bytes = hexToUint8Array(unknownInput.toHex())
      } else {
        throw new Error(`Bytes#constructor: unsupported type: ${typeof bytes}`)
      }
    }

    this.length = this.bytes.length

    if (byteLength !== undefined) {
      if (Array.isArray(byteLength)) {
        if (!byteLength.includes(this.length)) {
          throw new Error(
            `Bytes#checkByteLength: bytes length is ${this.length} but expected ${byteLength.join(' or ')}`,
          )
        }
      } else if (this.length !== byteLength) {
        throw new Error(`Bytes#checkByteLength: bytes length is ${this.length} but expected ${byteLength}`)
      }
    }
  }

  /**
   * Hashes `bytes` with keccak256 and wraps the 32-byte digest.
   */
  static keccak256(bytes: Uint8Array | ArrayBuffer | string | Bytes): Bytes {
    return new Bytes(keccak256(new Bytes(bytes).toUint8Array()))
  }

  /**
   * Concatenates any number of byte arrays (or Bytes instances) into one new array.
   */
  static concat(...arrays: (Uint8Array | Bytes)[]): Uint8Array {
    const normalized = arrays.map(array => (array instanceof Bytes ? array.toUint8Array() : array))
    const totalLength = normalized.reduce((sum, array) => sum + array.length, 0)
    const result = new Uint8Array(totalLength)
    let offset = 0

    for (const array of normalized) {
      result.set(array, offset)
      offset += array.length
    }

    return result
  }

  /**
   * Wraps the UTF-8 encoding of a string.
   */
  static fromUtf8(utf8: string): Bytes {
    return new Bytes(ENCODER.encode(utf8))
  }

  /**
   * Wraps a slice of `bytes` starting at `start`, running to the end unless
   * `length` is given.
   */
  static fromSlice(bytes: Uint8Array, start: number, length?: number): Bytes {
    if (length === undefined) {
      return new Bytes(bytes.slice(start))
    }
    return new Bytes(bytes.slice(start, start + length))
  }

  /**
   * Returns a copy of the bytes from `index` to the end.
   */
  offset(index: number): Uint8Array {
    return new Uint8Array(this.bytes.slice(index))
  }

  /**
   * Returns a copy of the underlying bytes.
   */
  public toUint8Array(): Uint8Array {
    return new Uint8Array(this.bytes)
  }

  /**
   * Encodes as a lowercase hex string, with no `0x` prefix.
   */
  public toHex(): string {
    return uint8ArrayToHex(this.bytes)
  }

  /**
   * Encodes as a padded base64 string.
   */
  public toBase64(): string {
    return uint8ArrayToBase64(this.bytes)
  }

  /**
   * Encodes as a padded base32 string.
   */
  public toBase32(): string {
    return uint8ArrayToBase32(this.bytes)
  }

  /**
   * Same as {@link toHex}.
   */
  public toString(): string {
    return this.toHex()
  }

  /**
   * Decodes the bytes as UTF-8 text.
   */
  public toUtf8(): string {
    return DECODER.decode(this.bytes)
  }

  /**
   * Decodes the bytes as UTF-8 JSON.
   */
  public toJSON(): unknown {
    return JSON.parse(this.toUtf8())
  }

  /**
   * Byte-wise equality against another Bytes instance, raw bytes, or hex string.
   */
  public equals(other: Bytes | Uint8Array | string): boolean {
    return this.toHex() === new Bytes(other).toHex()
  }

  /**
   * Human-readable representation, used by debuggers/loggers. Same as {@link toHex}.
   */
  public represent(): string {
    return this.toHex()
  }
}
