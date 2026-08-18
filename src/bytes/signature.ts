import { recoverPublicKey } from '../crypto/ecdsa.js'
import { keccak256 } from '../crypto/keccak.js'
import { Bytes } from './bytes.js'
import { numberToUint256, uint256ToNumber } from './encoding.js'
import { EthAddress } from './eth-address.js'
import { PublicKey } from './public-key.js'

const ENCODER = new TextEncoder()
const ETHEREUM_SIGNED_MESSAGE_PREFIX = ENCODER.encode('\x19Ethereum Signed Message:\n32')

/**
 * Ethereum's personal_sign convention: sign/recover against
 * keccak256(prefix || keccak256(data)) rather than signing `data` directly.
 * signMessage/recoverPublicKey (crypto/ecdsa.ts) each apply the outer
 * keccak256 themselves, so this only builds the prefix || keccak256(data) part.
 */
export function personalSignDigest(data: Uint8Array | string): Uint8Array {
  const bytes = data instanceof Uint8Array ? data : ENCODER.encode(data)

  return Bytes.concat(ETHEREUM_SIGNED_MESSAGE_PREFIX, keccak256(bytes))
}

/**
 * A 65-byte ECDSA signature (r || s || v), as produced by {@link PrivateKey.sign}.
 */
export class Signature extends Bytes {
  static readonly LENGTH = 65

  constructor(bytes: Uint8Array | string | Bytes) {
    super(bytes, 65)
  }

  /**
   * Reads a 65-byte Signature out of a larger buffer, starting at `start`.
   */
  static fromSlice(bytes: Uint8Array, start: number): Signature {
    return new Signature(bytes.slice(start, start + Signature.LENGTH))
  }

  /**
   * Recovers the public key that produced this signature over `digest`,
   * following the same personal_sign convention as {@link PrivateKey.sign}.
   */
  recoverPublicKey(digest: Uint8Array | string): PublicKey {
    const r = uint256ToNumber(this.bytes.slice(0, 32), 'BE')
    const s = uint256ToNumber(this.bytes.slice(32, 64), 'BE')
    const v = BigInt(this.bytes[64]!) as 27n | 28n
    const [x, y] = recoverPublicKey(personalSignDigest(digest), r, s, v)

    return new PublicKey(Bytes.concat(numberToUint256(x, 'BE'), numberToUint256(y, 'BE')))
  }

  /**
   * Returns whether this signature over `digest` was produced by the owner
   * of `expectedAddress`.
   */
  isValid(digest: Uint8Array | string, expectedAddress: EthAddress | Uint8Array | string): boolean {
    const publicKey = this.recoverPublicKey(digest)
    const address = publicKey.address()

    return address.equals(expectedAddress)
  }
}
