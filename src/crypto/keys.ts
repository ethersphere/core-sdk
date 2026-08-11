import { secp256k1 } from '@noble/curves/secp256k1.js'
import { numberToUint256, uint8ArrayToHex } from '../bytes/encoding.js'
import { keccak256 } from './keccak.js'
import { Bytes } from '../bytes/bytes.js'

/** The order of the secp256k1 curve's generator point. */
export const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n

/**
 * Derives the (uncompressed) public key point for a private key.
 * Throws if the private key is out of the valid `(0, SECP256K1_N)` range.
 */
export function privateKeyToPublicKey(privateKey: bigint): [bigint, bigint] {
  if (privateKey <= 0n || privateKey >= SECP256K1_N) {
    throw new Error('Invalid private key')
  }
  const point = secp256k1.Point.BASE.multiply(privateKey)
  return [point.x, point.y]
}

/**
 * Encodes a public key point as a 33-byte compressed key (0x02/0x03 prefix || x).
 */
export function compressPublicKey(publicKey: [bigint, bigint]): Uint8Array {
  return secp256k1.Point.fromAffine({ x: publicKey[0], y: publicKey[1] }).toBytes(true)
}

/**
 * Decompresses a 33-byte compressed public key back into its point.
 */
export function publicKeyFromCompressed(compressed: Uint8Array): [bigint, bigint] {
  if (compressed.length !== 33 || (compressed[0] !== 0x02 && compressed[0] !== 0x03)) {
    throw new Error('Invalid compressed public key')
  }
  const point = secp256k1.Point.fromBytes(compressed)
  return [point.x, point.y]
}

/**
 * Derives the Ethereum address for a public key point (keccak256 of the
 * uncompressed key, last 20 bytes).
 */
export function publicKeyToAddress(publicKey: [bigint, bigint]): Uint8Array {
  const address = new Uint8Array(20)
  const hash = keccak256(Bytes.concat(numberToUint256(publicKey[0], 'BE'), numberToUint256(publicKey[1], 'BE')))
  address.set(hash.subarray(12))
  return address
}

/**
 * EIP-55 checksum-cases an address's hex encoding (e.g. `0x5aAe...`).
 */
export function checksumEncode(addressBytes: Uint8Array): string {
  const address = uint8ArrayToHex(addressBytes)
  const addressAscii = Uint8Array.from(address, char => char.charCodeAt(0))
  const hash = uint8ArrayToHex(keccak256(addressAscii))
  let result = '0x'
  for (let i = 0; i < address.length; i++) {
    result += parseInt(hash.charAt(i), 16) > 7 ? address.charAt(i).toUpperCase() : address.charAt(i)
  }
  return result
}
