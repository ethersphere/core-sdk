import { describe, expect, it } from 'vitest'
import * as bytesModule from '../src/bytes/index.js'
import * as chunkModule from '../src/chunk/index.js'
import * as cryptoModule from '../src/crypto/index.js'
import * as encryptionModule from '../src/encryption/index.js'
import * as erasureCodingModule from '../src/erasure-coding/index.js'
import * as mantarayModule from '../src/mantaray/index.js'
import * as stamperModule from '../src/stamper/index.js'
import * as rootModule from '../src/index.js'

// This is the library's public contract: every subpath's exact export list.
// A name missing here means a breaking removal; a name here missing from the
// module means either an accidental omission or an accidental public leak
// (e.g. an internal constant that slipped into a barrel file).

const BYTES_EXPORTS = [
  'base32ToUint8Array',
  'base64ToUint8Array',
  'binaryToUint8Array',
  'commonPrefix',
  'equals',
  'hexToUint8Array',
  'indexOf',
  'numberToUint16',
  'numberToUint256',
  'numberToUint32',
  'numberToUint64',
  'numberToUint8',
  'partition',
  'sliceBytes',
  'uint16ToNumber',
  'uint256ToNumber',
  'uint32ToNumber',
  'uint64ToNumber',
  'uint8ArrayToBase32',
  'uint8ArrayToBase64',
  'uint8ArrayToBinary',
  'uint8ArrayToHex',
  'uint8ToNumber',
  'BatchId',
  'Bytes',
  'EthAddress',
  'FeedIndex',
  'Identifier',
  'PeerAddress',
  'PrivateKey',
  'PublicKey',
  'Reference',
  'Signature',
  'Span',
  'Topic',
  'TransactionId',
]

const CRYPTO_EXPORTS = [
  'keccak256',
  'checksumEncode',
  'compressPublicKey',
  'privateKeyToPublicKey',
  'publicKeyFromCompressed',
  'publicKeyToAddress',
  'recoverPublicKey',
  'signHash',
  'signMessage',
  'verifySignature',
]

const ENCRYPTION_EXPORTS = ['decryptChunk', 'encryptData', 'encryptSegments', 'encryptSpan', 'xorCypher']

const CHUNK_EXPORTS = [
  'Uint8ArrayReader',
  'Uint8ArrayWriter',
  'REPLICAS_OWNER',
  'calculateChunkAddress',
  'makeContentAddressedChunk',
  'unmarshalContentAddressedChunk',
  'MAX_PAYLOAD_SIZE',
  'MIN_PAYLOAD_SIZE',
  'ChunkBuilder',
  'ChunkSplitter',
  'ChunkJoiner',
  'makeSOCAddress',
  'makeSingleOwnerChunk',
  'unmarshalSingleOwnerChunk',
  'makeReplicas',
  'makeEncryptedReplicas',
]

const ERASURE_CODING_EXPORTS = [
  'rsEncode',
  'rsDecode',
  'getMaxShards',
  'getParities',
  'makeErasureBatch',
  'makeIntermediateChunkHandler',
  'approximateOverheadForRedundancyLevel',
  'getRedundancyStat',
  'getRedundancyStats',
  'decodeRedundancyLevel',
  'encodeRedundancyLevel',
  'referenceCount',
]

const STAMPER_EXPORTS = [
  'getStampTheoreticalBytes',
  'getStampUsage',
  'convertEnvelopeToMarshaledStamp',
  'marshalStamp',
  'getDepthForSize',
  'getStampEffectiveBytes',
  'getStampEffectiveBytesBreakpoints',
  'stamp',
  'Stamper',
]

const MANTARAY_EXPORTS = ['Fork', 'MantarayNode']

// Exports that are data, not callables (e.g. a fixed address constant) -
// exempted from the "every export is a function" check below.
const NON_FUNCTION_EXPORTS = new Set(['REPLICAS_OWNER', 'MAX_PAYLOAD_SIZE', 'MIN_PAYLOAD_SIZE'])

function assertExactExports(module: object, expectedNames: string[], label: string) {
  const actualNames = Object.keys(module).sort()
  expect(actualNames, `${label}: unexpected export list`).toEqual([...expectedNames].sort())
  for (const name of expectedNames) {
    if (NON_FUNCTION_EXPORTS.has(name)) {
      expect((module as Record<string, unknown>)[name], `${label}.${name} should be defined`).toBeDefined()
      continue
    }
    expect(typeof (module as Record<string, unknown>)[name], `${label}.${name} should be a function`).toBe('function')
  }
}

describe('public API contract', () => {
  it('swarm-core-lib/bytes exports exactly the expected functions', () => {
    assertExactExports(bytesModule, BYTES_EXPORTS, 'bytes')
  })

  it('swarm-core-lib/crypto exports exactly the expected functions', () => {
    assertExactExports(cryptoModule, CRYPTO_EXPORTS, 'crypto')
  })

  it('swarm-core-lib/encryption exports exactly the expected functions', () => {
    assertExactExports(encryptionModule, ENCRYPTION_EXPORTS, 'encryption')
  })

  it('swarm-core-lib/chunk exports exactly the expected classes and constants', () => {
    assertExactExports(chunkModule, CHUNK_EXPORTS, 'chunk')
  })

  it('swarm-core-lib/erasure-coding exports exactly the expected functions', () => {
    assertExactExports(erasureCodingModule, ERASURE_CODING_EXPORTS, 'erasure-coding')
  })

  it('swarm-core-lib/stamper exports exactly the expected functions', () => {
    assertExactExports(stamperModule, STAMPER_EXPORTS, 'stamper')
  })

  it('swarm-core-lib/mantaray exports exactly the expected classes', () => {
    assertExactExports(mantarayModule, MANTARAY_EXPORTS, 'mantaray')
  })

  it('swarm-core-lib (root) re-exports the union of every implemented subpath', () => {
    assertExactExports(
      rootModule,
      [
        ...BYTES_EXPORTS,
        ...CHUNK_EXPORTS,
        ...CRYPTO_EXPORTS,
        ...ENCRYPTION_EXPORTS,
        ...ERASURE_CODING_EXPORTS,
        ...MANTARAY_EXPORTS,
        ...STAMPER_EXPORTS,
      ],
      'root',
    )
  })
})
