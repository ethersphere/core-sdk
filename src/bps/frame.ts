import { Bytes } from '../bytes/bytes.js'
import { numberToUint64, uint64ToNumber } from '../bytes/encoding.js'
import { EthAddress } from '../bytes/eth-address.js'
import { Identifier } from '../bytes/identifier.js'
import { Span } from '../bytes/span.js'
import type { SingleOwnerChunk } from '../chunk/soc.js'
import { BPS_CHALLENGE_LENGTH, BpsKind } from './chunk.js'

const INDEX_LENGTH = 8
const DELIVERY_HEADER_LENGTH = 1 + EthAddress.LENGTH + BPS_CHALLENGE_LENGTH + INDEX_LENGTH
const SOC_PAYLOAD_OFFSET = Identifier.LENGTH + 65 + Span.LENGTH

export interface BpsDelivery {
  kind: BpsKind.Data | BpsKind.Eos | BpsKind.Roster
  owner: EthAddress
  challenge: Bytes
  index: bigint
  soc: Uint8Array
  payload: Bytes
}

export function encodeBpsPublishFrame(
  kind: BpsKind,
  index: bigint | number,
  soc: SingleOwnerChunk | Bytes | Uint8Array,
): Uint8Array {
  if (!(kind in BpsKind)) {
    throw new Error(`unknown bps kind ${kind}`)
  }

  const data = 'data' in soc ? soc.data : new Bytes(soc).toUint8Array()

  return Bytes.concat(new Uint8Array([kind]), numberToUint64(BigInt(index), 'BE'), data)
}

export function decodeBpsDeliveryFrame(frame: Bytes | Uint8Array): BpsDelivery {
  const bytes = new Bytes(frame).toUint8Array()

  if (bytes.length < DELIVERY_HEADER_LENGTH + SOC_PAYLOAD_OFFSET) {
    throw new Error(`bps delivery frame too short: ${bytes.length} bytes`)
  }

  const kind = bytes[0]!

  if (kind !== BpsKind.Data && kind !== BpsKind.Eos && kind !== BpsKind.Roster) {
    throw new Error(`unexpected bps delivery kind ${kind}`)
  }

  const challengeOffset = 1 + EthAddress.LENGTH
  const indexOffset = challengeOffset + BPS_CHALLENGE_LENGTH
  const soc = bytes.slice(DELIVERY_HEADER_LENGTH)

  return {
    kind,
    owner: new EthAddress(bytes.subarray(1, challengeOffset)),
    challenge: new Bytes(bytes.subarray(challengeOffset, indexOffset)),
    index: uint64ToNumber(bytes.subarray(indexOffset, DELIVERY_HEADER_LENGTH), 'BE'),
    soc,
    payload: new Bytes(soc.subarray(SOC_PAYLOAD_OFFSET)),
  }
}
