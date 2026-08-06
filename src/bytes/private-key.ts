import { signMessage } from '../crypto/ecdsa.js'
import { privateKeyToPublicKey } from '../crypto/keys.js'
import { Bytes } from './bytes.js'
import { concatBytes, numberToUint256, uint256ToNumber } from './encoding.js'
import { PublicKey } from './public-key.js'
import { personalSignDigest, Signature } from './signature.js'

/**
 * A 32-byte secp256k1 private key.
 */
export class PrivateKey extends Bytes {
  static readonly LENGTH = 32

  constructor(bytes: Uint8Array | string | Bytes) {
    super(bytes, 32)
  }

  /**
   * Derives the corresponding (uncompressed) public key.
   */
  publicKey(): PublicKey {
    const [x, y] = privateKeyToPublicKey(this.toBigInt())

    return new PublicKey(concatBytes(numberToUint256(x, 'BE'), numberToUint256(y, 'BE')))
  }

  /**
   * Signs `data` following Ethereum's personal_sign convention (signs
   * keccak256("\x19Ethereum Signed Message:\n32" || keccak256(data))).
   */
  sign(data: Uint8Array | string): Signature {
    const [r, s, v] = signMessage(personalSignDigest(data), this.toBigInt())

    return new Signature(concatBytes(numberToUint256(r, 'BE'), numberToUint256(s, 'BE'), new Uint8Array([Number(v)])))
  }

  /**
   * Decodes the private key as a bigint scalar, for use in ECDSA operations.
   */
  toBigInt(): bigint {
    return uint256ToNumber(this.bytes, 'BE')
  }
}
