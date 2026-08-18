import { base32ToUint8Array, uint8ArrayToBase32 } from './encoding.js'
import { Bytes } from './bytes.js'

const SWARM_MANIFEST_CODEC = 0xfa
const SWARM_FEED_CODEC = 0xfb

// Decodes a "bah5..." CID string into its reference bytes. The CID is a
// multibase-base32-lowercase-prefixed self-describing header (version=1,
// codec, "unknown" multihash, sha256, 32-byte digest length) followed by the
// base32-encoded 32-byte reference.
function decodeCid(cid: string): Uint8Array {
  const bytes = base32ToUint8Array(cid.toUpperCase().slice(1))
  const codec = bytes[1]

  if (codec !== SWARM_MANIFEST_CODEC && codec !== SWARM_FEED_CODEC) {
    throw new Error('Unknown codec')
  }

  return bytes.slice(-32)
}

/**
 * A Swarm chunk/manifest reference: 32 bytes for an unencrypted address, or
 * 64 bytes (address || decryption key) for an encrypted one. Also accepts a
 * `"bah5..."` CID string, decoding it to the underlying reference bytes.
 */
export class Reference extends Bytes {
  static readonly LENGTH = 32

  constructor(bytes: Uint8Array | string | Bytes) {
    if (typeof bytes === 'string' && bytes.startsWith('bah5')) {
      super(decodeCid(bytes), 32)
    } else {
      super(bytes, [32, 64])
    }
  }

  /**
   * Encodes the reference as a `"bah5..."` CID string of the given type.
   */
  toCid(type: 'feed' | 'manifest'): string {
    const header = Bytes.concat(
      new Uint8Array([1]), // version
      new Uint8Array([type === 'feed' ? SWARM_FEED_CODEC : SWARM_MANIFEST_CODEC]),
      new Uint8Array([1]), // "unknown" multihash
      new Uint8Array([27]), // sha256
      new Uint8Array([32]), // 32-byte digest length
    )

    return `b${uint8ArrayToBase32(header).replace(/=+$/, '')}${this.toBase32().replace(/=+$/, '')}`.toLowerCase()
  }

  /**
   * Returns whether `value` parses as a valid Reference (raw hex, 32/64-byte
   * bytes, or a `"bah5..."` CID string).
   */
  static isValid(value: string): boolean {
    try {
      new Reference(value)

      return true
    } catch {
      return false
    }
  }
}
