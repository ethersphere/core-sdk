/**
 * Splits `bytes` into consecutive chunks of `size` bytes. The final chunk is
 * shorter if `bytes.length` isn't a multiple of `size`. Returned chunks are
 * views into `bytes`, not copies.
 */
export function partition(bytes: Uint8Array, size: number): Uint8Array[] {
  const partitions: Uint8Array[] = []
  for (let i = 0; i < bytes.length; i += size) {
    partitions.push(bytes.subarray(i, i + size))
  }
  return partitions
}

/**
 * Byte-wise equality check. `false` if the lengths differ.
 */
export function equals(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false
  }
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) {
      return false
    }
  }
  return true
}

/**
 * Returns the longest shared leading run of bytes between `one` and `other`.
 */
export function commonPrefix(one: Uint8Array, other: Uint8Array): Uint8Array {
  const length = Math.min(one.length, other.length)
  for (let i = 0; i < length; i++) {
    if (one[i] !== other[i]) {
      return one.subarray(0, i)
    }
  }
  return one.subarray(0, length)
}

/**
 * Finds the first index at or after `start` where `value` occurs as a
 * contiguous subsequence of `bytes`, or -1 if it doesn't occur.
 */
export function indexOf(bytes: Uint8Array, value: Uint8Array, start = 0): number {
  for (let i = start; i < bytes.length; i++) {
    for (let j = 0; j < value.length; j++) {
      if (bytes[i + j] !== value[j]) {
        break
      }
      if (j === value.length - 1) {
        return i
      }
    }
  }
  return -1
}

/**
 * Encodes bytes as a lowercase hex string, with no `0x` prefix.
 */
export function uint8ArrayToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * Encodes a bigint as a fixed-width 32-byte array.
 */
export function numberToUint256(value: bigint, endian: 'LE' | 'BE'): Uint8Array {
  const bytes = new Uint8Array(32)
  let remaining = value
  if (endian === 'LE') {
    for (let i = 0; i < 32; i++) {
      bytes[i] = Number(remaining & 0xffn)
      remaining >>= 8n
    }
    return bytes
  }
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(remaining & 0xffn)
    remaining >>= 8n
  }
  return bytes
}

/**
 * Decodes a 32-byte array into a bigint.
 */
export function uint256ToNumber(bytes: Uint8Array, endian: 'LE' | 'BE'): bigint {
  let result = 0n
  if (endian === 'LE') {
    for (let i = 31; i >= 0; i--) {
      result = (result << 8n) | BigInt(bytes[i]!)
    }
    return result
  }
  for (let i = 0; i < 32; i++) {
    result = (result << 8n) | BigInt(bytes[i]!)
  }
  return result
}

/**
 * Decodes a hex string (with or without a `0x`/`0X` prefix) into bytes.
 */
export function hexToUint8Array(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex
  const result = new Uint8Array(clean.length / 2)
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16)
  }
  return result
}

const BASE64_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

function baseToUint8Array(baseString: string, baseChars: string): Uint8Array {
  const padding = '='
  const base = baseChars.length
  let bits = 0
  let value = 0
  const array: number[] = []
  for (let i = 0; i < baseString.length; i++) {
    const character = baseString.charAt(i)
    if (character === padding) {
      break
    }
    const index = baseChars.indexOf(character)
    if (index === -1) {
      throw new Error(`Invalid character: ${character}`)
    }
    value = (value << Math.log2(base)) | index
    bits += Math.log2(base)
    if (bits >= 8) {
      bits -= 8
      array.push((value >> bits) & 0xff)
    }
  }
  return new Uint8Array(array)
}

function uint8ArrayToBase(bytes: Uint8Array, baseChars: string): string {
  const base = baseChars.length
  let bits = 0
  let value = 0
  let result = ''
  for (const byte of bytes) {
    value = (value << 8) | byte
    bits += 8
    while (bits >= Math.log2(base)) {
      bits -= Math.log2(base)
      result += baseChars.charAt((value >> bits) & (base - 1))
    }
  }
  if (bits > 0) {
    result += baseChars.charAt((value << (Math.log2(base) - bits)) & (base - 1))
  }
  if (result.length % 4 !== 0) {
    result += '='.repeat(4 - (result.length % 4))
  }
  return result
}

/**
 * Decodes a (padded) base64 string into bytes.
 */
export function base64ToUint8Array(base64: string): Uint8Array {
  return baseToUint8Array(base64, BASE64_CHARS)
}

/**
 * Encodes bytes as a padded base64 string.
 */
export function uint8ArrayToBase64(bytes: Uint8Array): string {
  return uint8ArrayToBase(bytes, BASE64_CHARS)
}

/**
 * Decodes a (padded) base32 string into bytes.
 */
export function base32ToUint8Array(base32: string): Uint8Array {
  return baseToUint8Array(base32, BASE32_CHARS)
}

/**
 * Encodes bytes as a padded base32 string.
 */
export function uint8ArrayToBase32(bytes: Uint8Array): string {
  return uint8ArrayToBase(bytes, BASE32_CHARS)
}

/**
 * Encodes bytes as a string of `'0'`/`'1'` characters, 8 per byte.
 */
export function uint8ArrayToBinary(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(byte => byte.toString(2).padStart(8, '0'))
    .join('')
}

/**
 * Decodes a string of `'0'`/`'1'` characters (8 per byte) into bytes.
 */
export function binaryToUint8Array(binary: string): Uint8Array {
  const result = new Uint8Array(Math.ceil(binary.length / 8))
  for (let i = 0; i < result.length; i++) {
    result[i] = parseInt(binary.slice(i * 8, i * 8 + 8), 2)
  }
  return result
}

/**
 * Splits `bytes` into consecutive sub-arrays of the given `lengths`, in order.
 */
export function sliceBytes(bytes: Uint8Array, lengths: number[]): Uint8Array[] {
  const result: Uint8Array[] = []
  let offset = 0
  for (const length of lengths) {
    result.push(bytes.subarray(offset, offset + length))
    offset += length
  }
  return result
}

/**
 * Wraps a single byte value in a 1-byte array.
 */
export function numberToUint8(value: number): Uint8Array {
  return new Uint8Array([value])
}

/**
 * Reads the first byte of a 1-byte array as a number.
 */
export function uint8ToNumber(bytes: Uint8Array): number {
  return bytes[0]!
}

/**
 * Encodes a number as a fixed-width 2-byte array.
 */
export function numberToUint16(value: number, endian: 'LE' | 'BE'): Uint8Array {
  const buffer = new ArrayBuffer(2)
  new DataView(buffer).setUint16(0, value, endian === 'LE')
  return new Uint8Array(buffer)
}

/**
 * Decodes a 2-byte array into a number.
 */
export function uint16ToNumber(bytes: Uint8Array, endian: 'LE' | 'BE'): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint16(0, endian === 'LE')
}

/**
 * Encodes a number as a fixed-width 4-byte array.
 */
export function numberToUint32(value: number, endian: 'LE' | 'BE'): Uint8Array {
  const buffer = new ArrayBuffer(4)
  new DataView(buffer).setUint32(0, value, endian === 'LE')
  return new Uint8Array(buffer)
}

/**
 * Decodes a 4-byte array into a number.
 */
export function uint32ToNumber(bytes: Uint8Array, endian: 'LE' | 'BE'): number {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0, endian === 'LE')
}

/**
 * Encodes a bigint as a fixed-width 8-byte array.
 */
export function numberToUint64(value: bigint, endian: 'LE' | 'BE'): Uint8Array {
  const buffer = new ArrayBuffer(8)
  new DataView(buffer).setBigUint64(0, value, endian === 'LE')
  return new Uint8Array(buffer)
}

/**
 * Decodes an 8-byte array into a bigint.
 */
export function uint64ToNumber(bytes: Uint8Array, endian: 'LE' | 'BE'): bigint {
  return new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getBigUint64(0, endian === 'LE')
}
