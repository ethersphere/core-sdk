import { compressPublicKey, publicKeyFromCompressed, publicKeyToAddress } from '../crypto/keys.js'
import { Bytes } from './bytes.js'
import { numberToUint256, uint256ToNumber, uint8ArrayToHex } from './encoding.js'
import { EthAddress } from './eth-address.js'

/**
 * A secp256k1 public key, stored uncompressed (64 bytes: x || y). Also
 * accepts a 33-byte compressed key, decompressing it in the constructor.
 */
export class PublicKey extends Bytes {
  static readonly LENGTH = 64

  constructor(bytes: Uint8Array | string | Bytes) {
    const uncompressed = new Bytes(bytes)

    if (uncompressed.length === 33) {
      const [x, y] = publicKeyFromCompressed(uncompressed.toUint8Array())
      super(Bytes.concat(numberToUint256(x, 'BE'), numberToUint256(y, 'BE')), 64)
    } else {
      super(bytes, 64)
    }
  }

  /**
   * Derives the corresponding Ethereum address (keccak256 of the
   * uncompressed key, last 20 bytes).
   */
  address(): EthAddress {
    const x = uint256ToNumber(this.bytes.slice(0, 32), 'BE')
    const y = uint256ToNumber(this.bytes.slice(32, 64), 'BE')

    return new EthAddress(publicKeyToAddress([x, y]))
  }

  /**
   * Encodes as a 33-byte compressed key (0x02/0x03 prefix || x).
   */
  toCompressedUint8Array(): Uint8Array {
    const x = uint256ToNumber(this.bytes.slice(0, 32), 'BE')
    const y = uint256ToNumber(this.bytes.slice(32, 64), 'BE')

    return compressPublicKey([x, y])
  }

  /**
   * Hex encoding of {@link toCompressedUint8Array}.
   */
  toCompressedHex(): string {
    return uint8ArrayToHex(this.toCompressedUint8Array())
  }
}
