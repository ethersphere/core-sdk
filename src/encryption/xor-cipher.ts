/**
 * XORs `bytes` against `key`, repeating the key as needed. Symmetric - the
 * same function both encrypts and decrypts. Used for Mantaray's per-node
 * obfuscation key.
 */
export function xorCypher(bytes: Uint8Array, key: Uint8Array): Uint8Array {
  if (key.length === 0) {
    throw new Error('xorCypher: key must not be empty')
  }
  const result = new Uint8Array(bytes.length)
  for (let i = 0; i < bytes.length; i++) {
    result[i] = bytes[i]! ^ key[i % key.length]!
  }
  return result
}
