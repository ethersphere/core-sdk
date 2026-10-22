import { Bytes } from '../bytes/bytes.js'
import { EthAddress } from '../bytes/eth-address.js'

export const BPS_MAX_ROSTER_SIZE = 186

const PUBLISHERS_FIELD = 1
const WIRE_VARINT = 0
const WIRE_FIXED64 = 1
const WIRE_LENGTH_DELIMITED = 2
const WIRE_FIXED32 = 5
const MAX_VARINT_LENGTH = 10

export function encodeBpsRoster(publishers: (EthAddress | Uint8Array | string)[]): Uint8Array {
  if (publishers.length > BPS_MAX_ROSTER_SIZE) {
    throw new RangeError(`bps roster has ${publishers.length} publishers, maximum is ${BPS_MAX_ROSTER_SIZE}`)
  }

  const tag = (PUBLISHERS_FIELD << 3) | WIRE_LENGTH_DELIMITED

  return Bytes.concat(
    ...publishers.map(publisher => Bytes.concat(new Uint8Array([tag, EthAddress.LENGTH]), new EthAddress(publisher))),
  )
}

export function decodeBpsRoster(payload: Bytes | Uint8Array): EthAddress[] {
  const bytes = new Bytes(payload).toUint8Array()
  const publishers: EthAddress[] = []
  let offset = 0

  const readVarint = (): number => {
    let value = 0

    for (let i = 0; i < MAX_VARINT_LENGTH && offset < bytes.length; i++) {
      const byte = bytes[offset++]!
      value += (byte & 0x7f) * 2 ** (7 * i)

      if (byte < 0x80) {
        return value
      }
    }

    throw new Error('bps roster: malformed varint')
  }

  const skip = (length: number): void => {
    if (offset + length > bytes.length) {
      throw new Error('bps roster: truncated field')
    }
    offset += length
  }

  while (offset < bytes.length) {
    const tag = readVarint()
    const field = Math.floor(tag / 8)
    const wireType = tag % 8

    if (field === 0 || (field === PUBLISHERS_FIELD && wireType !== WIRE_LENGTH_DELIMITED)) {
      throw new Error(`bps roster: invalid tag ${tag}`)
    }

    switch (wireType) {
      case WIRE_VARINT:
        readVarint()
        break
      case WIRE_FIXED64:
        skip(8)
        break
      case WIRE_FIXED32:
        skip(4)
        break
      case WIRE_LENGTH_DELIMITED: {
        const length = readVarint()
        const start = offset
        skip(length)

        if (field === PUBLISHERS_FIELD) {
          if (length !== EthAddress.LENGTH) {
            throw new Error(`bps roster: address length ${length}`)
          }
          publishers.push(new EthAddress(bytes.subarray(start, offset)))
        }
        break
      }
      default:
        throw new Error(`bps roster: unsupported wire type ${wireType}`)
    }
  }

  return publishers
}
