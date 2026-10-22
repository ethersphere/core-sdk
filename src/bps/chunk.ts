import { Bytes } from '../bytes/bytes.js'
import { numberToUint64 } from '../bytes/encoding.js'
import { EthAddress } from '../bytes/eth-address.js'
import { Identifier } from '../bytes/identifier.js'
import { PrivateKey } from '../bytes/private-key.js'
import { Span } from '../bytes/span.js'
import { Topic } from '../bytes/topic.js'
import { makeChunkUnchecked, MAX_PAYLOAD_SIZE } from '../chunk/cac.js'
import { makeSingleOwnerChunk, makeSOCAddress, SingleOwnerChunk, unmarshalSingleOwnerChunk } from '../chunk/soc.js'
import { keccak256 } from '../crypto/keccak.js'
import { decodeBpsRoster } from './roster.js'

export enum BpsKind {
  Data = 1,
  Auth = 2,
  Eos = 3,
  Roster = 4,
}

export const BPS_CHALLENGE_LENGTH = 32

const SERVICE_PREFIX = new TextEncoder().encode('bps-service:v1')
const MAX_INDEX = 2n ** 64n - 1n
const SOC_HEADER_LENGTH = Identifier.LENGTH + 65 + Span.LENGTH

function isEmptyKind(kind: BpsKind): boolean {
  return kind === BpsKind.Auth || kind === BpsKind.Eos
}

function toIndex(index: bigint | number): bigint {
  const value = BigInt(index)

  if (value < 0n || value >= MAX_INDEX) {
    throw new RangeError(`bps index ${value} out of range`)
  }

  return value
}

function assertEmptyKindAtZero(kind: BpsKind, index: bigint): void {
  if (isEmptyKind(kind) && index !== 0n) {
    throw new RangeError(`bps ${BpsKind[kind]} chunk must be at index 0, got ${index}`)
  }
}

export function bpsSessionTopic(
  kind: BpsKind,
  topic: Topic | Uint8Array | string,
  challenge: Bytes | Uint8Array | string,
): Topic {
  const prefix = kind === BpsKind.Data ? new Uint8Array() : Bytes.concat(SERVICE_PREFIX, new Uint8Array([kind]))

  return new Topic(keccak256(Bytes.concat(prefix, new Topic(topic), new Bytes(challenge, BPS_CHALLENGE_LENGTH))))
}

export function bpsIdentifier(
  kind: BpsKind,
  topic: Topic | Uint8Array | string,
  challenge: Bytes | Uint8Array | string,
  index: bigint | number,
): Identifier {
  const sessionTopic = bpsSessionTopic(kind, topic, challenge)

  return new Identifier(keccak256(Bytes.concat(sessionTopic, numberToUint64(toIndex(index), 'BE'))))
}

export function makeBpsChunk(
  kind: BpsKind,
  topic: Topic | Uint8Array | string,
  challenge: Bytes | Uint8Array | string,
  index: bigint | number,
  privateKey: PrivateKey | Uint8Array | string,
  payload: Bytes | Uint8Array | string = new Uint8Array(),
): SingleOwnerChunk {
  const data = typeof payload === 'string' ? Bytes.fromUtf8(payload) : new Bytes(payload)
  const value = toIndex(index)
  assertEmptyKindAtZero(kind, value)

  if (isEmptyKind(kind) && data.length > 0) {
    throw new RangeError(`bps ${BpsKind[kind]} chunk must have no payload`)
  }

  if (data.length > MAX_PAYLOAD_SIZE) {
    throw new RangeError(`payload size ${data.length} exceeds maximum ${MAX_PAYLOAD_SIZE}`)
  }

  if (kind === BpsKind.Roster) {
    decodeBpsRoster(data)
  }

  const chunk = makeChunkUnchecked(data, Span.fromBigInt(BigInt(data.length)))
  const identifier = bpsIdentifier(kind, topic, challenge, value)

  return makeSingleOwnerChunk(chunk, identifier, new PrivateKey(privateKey).toBigInt())
}

export function verifyBpsChunk(
  frame: {
    kind: BpsKind
    owner: EthAddress | Uint8Array | string
    challenge: Bytes | Uint8Array | string
    index: bigint | number
    soc: Bytes | Uint8Array
  },
  topic: Topic | Uint8Array | string,
): SingleOwnerChunk {
  const data = new Bytes(frame.soc).toUint8Array()
  const index = toIndex(frame.index)
  assertEmptyKindAtZero(frame.kind, index)

  if (data.length < SOC_HEADER_LENGTH || data.length > SOC_HEADER_LENGTH + MAX_PAYLOAD_SIZE) {
    throw new Error(`bps chunk length ${data.length} out of range`)
  }

  if (isEmptyKind(frame.kind)) {
    const span = Span.fromSlice(data, SOC_HEADER_LENGTH - Span.LENGTH).toBigInt()

    if (data.length !== SOC_HEADER_LENGTH || span !== 0n) {
      throw new Error(`bps ${BpsKind[frame.kind]} chunk is not empty`)
    }
  }

  const identifier = bpsIdentifier(frame.kind, topic, frame.challenge, index)

  return unmarshalSingleOwnerChunk(data, makeSOCAddress(identifier, frame.owner))
}
