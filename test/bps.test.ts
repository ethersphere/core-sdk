import { describe, expect, it } from 'vitest'
import {
  BpsKind,
  BpsPosition,
  bpsIdentifier,
  bpsSessionTopic,
  decodeBpsDeliveryFrame,
  decodeBpsRoster,
  encodeBpsPublishFrame,
  encodeBpsRoster,
  makeBpsChunk,
  verifyBpsChunk,
} from '../src/bps/index.js'
import { Bytes } from '../src/bytes/bytes.js'
import { hexToUint8Array, numberToUint64 } from '../src/bytes/encoding.js'

// Vectors produced by pkg/bps of ethersphere/bee#5626 for these inputs.
const TOPIC = '11'.repeat(32)
const CHALLENGE = '22'.repeat(32)
const PRIVATE_KEY = '4f3edf983ac636a65a842ce7c78d9aa706d3b113bce9c46f30d7d21715b23b1d'
const OWNER = '90f8bf6a479f320ead074411a4b0e7944ea8c9c1'
const SEAT_A = 'aa'.repeat(20)
const SEAT_B = 'bb'.repeat(20)

const GO = {
  topics: {
    [BpsKind.Data]: '3e92e0db88d6afea9edc4eedf62fffa4d92bcdfc310dccbe943747fe8302e871',
    [BpsKind.Auth]: 'bc50d4f3a3c9e222fa67eb5d9f6e819c732d4ec2ef0afa4b1019a90e31d50c91',
    [BpsKind.Eos]: '2b69db07c90ae59f59e7a98814e9bdda892828e4bd92d9868520f3a2c948ff48',
    [BpsKind.Roster]: '721a41a64d068b9191849b9d49ef375b7e50f6a338c19eac7773e8a59b7c87d9',
  },
  idsAt7: {
    [BpsKind.Data]: 'ae070cf6479865d199201674c717c4bf0135cbbc9baf9ca1ba70b82f12f84d77',
    [BpsKind.Auth]: 'd6a4eb8db411721b269362109a352b17d3dec0176a05815c258dccfbb37441b4',
    [BpsKind.Eos]: '23721f917432ac955e91aae05b8231a19802680f764582095da2104ab6511100',
    [BpsKind.Roster]: '993116f4d852e7bdd43a4958263af3eb25746082e85e6f1d4e405d33c764b9b3',
  },
  roster: '0a14aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a14bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  socData:
    'ae070cf6479865d199201674c717c4bf0135cbbc9baf9ca1ba70b82f12f84d77d8e7a693b04c624efad3b8b1fa27d46431f69f14e162187aae0c783e6fae78a940cecfa3059bb46572cb0232779c040d35a0892f0982dfea7b11f9e3ddf8f8a51b050000000000000068656c6c6f',
  socAuth:
    '98d2e75f56f7b58ec9d0901a28e6da2c3dfd9501e53199162311e72c699e5f7cde722614162c8fa77821802811be91c0f41e45b9dcfe3d797d97720a3a2400117adc1634a7c06403c47f3e96c24e2996928ec03ae1c9b5307622c4c3f1ac98ab1c0000000000000000',
  socRoster:
    '7187856fa68c0abb50f4b092a6bd49ce0ce072be2530a09d8f5694913b7b289e34cf682538ded3a77b0139f23a2816838b5d4beeb2140c76659382188ccf5c4045030f3dbad26acb0be3c764202facd2725230b739f0581cb645de458306385d1c2c000000000000000a14aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0a14bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
}

const KINDS = [BpsKind.Data, BpsKind.Auth, BpsKind.Eos, BpsKind.Roster] as const

function deliveryFrame(kind: BpsKind, owner: string, index: bigint, soc: string): Uint8Array {
  return Bytes.concat(
    new Uint8Array([kind]),
    hexToUint8Array(owner),
    hexToUint8Array(CHALLENGE),
    numberToUint64(index, 'BE'),
    hexToUint8Array(soc),
  )
}

describe('bpsSessionTopic / bpsIdentifier', () => {
  it.each(KINDS)('matches bee for kind %i', kind => {
    expect(bpsSessionTopic(kind, TOPIC, CHALLENGE).toHex()).toBe(GO.topics[kind])
    expect(bpsIdentifier(kind, TOPIC, CHALLENGE, 7n).toHex()).toBe(GO.idsAt7[kind])
    expect(bpsIdentifier(kind, TOPIC, CHALLENGE, 7).toHex()).toBe(GO.idsAt7[kind])
  })

  it('rejects a challenge of the wrong length', () => {
    expect(() => bpsSessionTopic(BpsKind.Data, TOPIC, '22'.repeat(31))).toThrow()
  })

  it('rejects the last uint64 index and negatives', () => {
    expect(() => bpsIdentifier(BpsKind.Data, TOPIC, CHALLENGE, 2n ** 64n - 1n)).toThrow(RangeError)
    expect(() => bpsIdentifier(BpsKind.Data, TOPIC, CHALLENGE, -1)).toThrow(RangeError)
  })
})

describe('makeBpsChunk', () => {
  it('builds the same DATA chunk as bee', () => {
    const soc = makeBpsChunk(BpsKind.Data, TOPIC, CHALLENGE, 7n, PRIVATE_KEY, 'hello')
    expect(new Bytes(soc.data).toHex()).toBe(GO.socData)
    expect(soc.owner.toHex()).toBe(OWNER)
  })

  it('builds the same empty AUTH chunk as bee', () => {
    const soc = makeBpsChunk(BpsKind.Auth, TOPIC, CHALLENGE, 0n, PRIVATE_KEY)
    expect(new Bytes(soc.data).toHex()).toBe(GO.socAuth)
    expect(soc.payload.length).toBe(0)
  })

  it('builds the same ROSTER chunk as bee', () => {
    const soc = makeBpsChunk(BpsKind.Roster, TOPIC, CHALLENGE, 1n, PRIVATE_KEY, encodeBpsRoster([SEAT_A, SEAT_B]))
    expect(new Bytes(soc.data).toHex()).toBe(GO.socRoster)
  })

  it('allows an empty roster', () => {
    const soc = makeBpsChunk(BpsKind.Roster, TOPIC, CHALLENGE, 2n, PRIVATE_KEY, encodeBpsRoster([]))
    expect(soc.payload.length).toBe(0)
  })

  it('rejects AUTH and EOS chunks off index 0 or with a payload', () => {
    expect(() => makeBpsChunk(BpsKind.Auth, TOPIC, CHALLENGE, 1n, PRIVATE_KEY)).toThrow(RangeError)
    expect(() => makeBpsChunk(BpsKind.Eos, TOPIC, CHALLENGE, 0n, PRIVATE_KEY, 'x')).toThrow(RangeError)
  })

  it('rejects a roster payload that does not decode', () => {
    expect(() =>
      makeBpsChunk(BpsKind.Roster, TOPIC, CHALLENGE, 0n, PRIVATE_KEY, new Uint8Array([0x0a, 0x02, 1, 2])),
    ).toThrow()
  })

  it('rejects an oversized payload', () => {
    expect(() => makeBpsChunk(BpsKind.Data, TOPIC, CHALLENGE, 0n, PRIVATE_KEY, new Uint8Array(4097))).toThrow(
      RangeError,
    )
  })
})

describe('verifyBpsChunk', () => {
  const data = { kind: BpsKind.Data, owner: OWNER, challenge: CHALLENGE, index: 7n, soc: hexToUint8Array(GO.socData) }

  it('accepts chunks signed by bee', () => {
    expect(verifyBpsChunk(data, TOPIC).payload.toUtf8()).toBe('hello')
    expect(
      verifyBpsChunk({ ...data, kind: BpsKind.Auth, index: 0n, soc: hexToUint8Array(GO.socAuth) }, TOPIC).payload
        .length,
    ).toBe(0)
    expect(
      verifyBpsChunk(
        { ...data, kind: BpsKind.Roster, index: 1n, soc: hexToUint8Array(GO.socRoster) },
        TOPIC,
      ).owner.toHex(),
    ).toBe(OWNER)
  })

  it('rejects a chunk whose frame fields do not derive its id', () => {
    expect(() => verifyBpsChunk({ ...data, index: 8n }, TOPIC)).toThrow()
    expect(() => verifyBpsChunk({ ...data, kind: BpsKind.Roster }, TOPIC)).toThrow()
    expect(() => verifyBpsChunk({ ...data, challenge: '33'.repeat(32) }, TOPIC)).toThrow()
    expect(() => verifyBpsChunk(data, '12'.repeat(32))).toThrow()
  })

  it('rejects a chunk signed by someone else', () => {
    expect(() => verifyBpsChunk({ ...data, owner: SEAT_A }, TOPIC)).toThrow()
  })

  it('rejects a non-empty AUTH chunk', () => {
    const auth = makeBpsChunk(BpsKind.Auth, TOPIC, CHALLENGE, 0n, PRIVATE_KEY)
    const padded = Bytes.concat(auth.data, new Uint8Array([0]))
    expect(() => verifyBpsChunk({ ...data, kind: BpsKind.Auth, index: 0n, soc: padded }, TOPIC)).toThrow()
  })

  it('rejects a truncated chunk', () => {
    expect(() => verifyBpsChunk({ ...data, soc: new Uint8Array(50) }, TOPIC)).toThrow()
  })
})

describe('encodeBpsRoster / decodeBpsRoster', () => {
  it('encodes the same payload as bee', () => {
    expect(new Bytes(encodeBpsRoster([SEAT_A, SEAT_B])).toHex()).toBe(GO.roster)
  })

  it('round-trips', () => {
    expect(decodeBpsRoster(hexToUint8Array(GO.roster)).map(address => address.toHex())).toEqual([SEAT_A, SEAT_B])
    expect(decodeBpsRoster(new Uint8Array())).toEqual([])
  })

  it('skips unknown fields', () => {
    const unknown = new Uint8Array([0x10, 0x96, 0x01, 0x1a, 0x01, 0xff, 0x25, 1, 2, 3, 4, 0x29, 1, 2, 3, 4, 5, 6, 7, 8])
    const decoded = decodeBpsRoster(Bytes.concat(unknown, hexToUint8Array(GO.roster)))
    expect(decoded.map(address => address.toHex())).toEqual([SEAT_A, SEAT_B])
  })

  it('rejects malformed payloads', () => {
    expect(() => decodeBpsRoster(new Uint8Array([0x0a, 0x13, ...new Uint8Array(19)]))).toThrow()
    expect(() => decodeBpsRoster(new Uint8Array([0x0a, 0x14, 1, 2]))).toThrow()
    expect(() => decodeBpsRoster(new Uint8Array([0x08, 0x01]))).toThrow()
    expect(() => decodeBpsRoster(new Uint8Array([0x0b]))).toThrow()
    expect(() => decodeBpsRoster(new Uint8Array([0x10, 0x80]))).toThrow()
  })

  it('caps the roster at what fits in one chunk', () => {
    const full = Array.from({ length: 186 }, () => SEAT_A)
    expect(encodeBpsRoster(full).length).toBeLessThanOrEqual(4096)
    expect(() => encodeBpsRoster([...full, SEAT_B])).toThrow(RangeError)
  })
})

describe('encodeBpsPublishFrame', () => {
  it('prefixes the chunk with kind and big-endian index', () => {
    const soc = makeBpsChunk(BpsKind.Data, TOPIC, CHALLENGE, 258n, PRIVATE_KEY, 'hi')
    const frame = encodeBpsPublishFrame(BpsKind.Data, 258n, soc)
    expect(new Bytes(frame.subarray(0, 9)).toHex()).toBe('010000000000000102')
    expect(frame.subarray(9)).toEqual(soc.data)
    expect(encodeBpsPublishFrame(BpsKind.Data, 258, soc.data)).toEqual(frame)
  })
})

describe('decodeBpsDeliveryFrame', () => {
  it('decodes the delivery header and chunk', () => {
    const delivery = decodeBpsDeliveryFrame(deliveryFrame(BpsKind.Data, OWNER, 7n, GO.socData))
    expect(delivery.kind).toBe(BpsKind.Data)
    expect(delivery.owner.toHex()).toBe(OWNER)
    expect(delivery.challenge.toHex()).toBe(CHALLENGE)
    expect(delivery.index).toBe(7n)
    expect(delivery.payload.toUtf8()).toBe('hello')
    expect(verifyBpsChunk(delivery, TOPIC).payload.toUtf8()).toBe('hello')
  })

  it('rejects AUTH and unknown kinds', () => {
    expect(() => decodeBpsDeliveryFrame(deliveryFrame(BpsKind.Auth, OWNER, 0n, GO.socAuth))).toThrow()
    expect(() => decodeBpsDeliveryFrame(deliveryFrame(9 as BpsKind, OWNER, 0n, GO.socAuth))).toThrow()
  })

  it('rejects a short frame', () => {
    expect(() => decodeBpsDeliveryFrame(new Uint8Array(100))).toThrow()
  })
})

describe('BpsPosition', () => {
  const data = (owner: string, index: bigint) => ({ kind: BpsKind.Data, owner, index, payload: new Uint8Array() })
  const roster = (index: bigint, publishers: string[]) => ({
    kind: BpsKind.Roster,
    owner: OWNER,
    index,
    payload: encodeBpsRoster(publishers),
  })

  it('starts at zero and accepts only the owner', () => {
    const position = new BpsPosition(OWNER)
    expect(position.toQuery()).toEqual({ cursor: '0', rosterCursor: '0' })
    expect(position.accept(data(SEAT_A, 0n))).toBe(false)
    expect(position.accept(data(OWNER, 3n))).toBe(true)
    expect(position.cursor()).toBe(4n)
  })

  it('drops updates below a publisher cursor', () => {
    const position = new BpsPosition(OWNER, { cursor: 10n })
    expect(position.accept(data(OWNER, 9n))).toBe(false)
    expect(position.accept(data(OWNER, 10n))).toBe(true)
    expect(position.accept(data(OWNER, 10n))).toBe(false)
  })

  it('admits the publishers of the latest roster only', () => {
    const position = new BpsPosition(OWNER)
    expect(position.accept(roster(0n, [SEAT_A]))).toBe(true)
    expect(position.accept(data(SEAT_A, 5n))).toBe(true)
    expect(position.accept(roster(1n, [SEAT_B]))).toBe(true)
    expect(position.accept(data(SEAT_A, 6n))).toBe(false)
    expect(position.accept(data(SEAT_B, 0n))).toBe(true)
    expect(position.roster.map(address => address.toHex())).toEqual([SEAT_B])
  })

  it('ignores a roster below the roster cursor', () => {
    const position = new BpsPosition(OWNER)
    position.accept(roster(4n, [SEAT_A]))
    expect(position.accept(roster(4n, [SEAT_B]))).toBe(false)
    expect(position.accept(roster(2n, [SEAT_B]))).toBe(false)
    expect(position.rosterCursor).toBe(5n)
    expect(position.roster.map(address => address.toHex())).toEqual([SEAT_A])
  })

  it('marks the channel ended on EOS', () => {
    const position = new BpsPosition(OWNER)
    const eos = { kind: BpsKind.Eos, owner: OWNER, index: 0n, payload: new Uint8Array() }
    expect(position.accept(eos)).toBe(true)
    expect(position.ended).toBe(true)
    expect(position.accept(eos)).toBe(false)
  })

  it('serializes the query the subscribe endpoint expects and restores from it', () => {
    const position = new BpsPosition(OWNER)
    position.accept(data(OWNER, 6n))
    position.accept(roster(2n, [SEAT_A, SEAT_B]))
    position.accept(data(SEAT_A, 3n))
    expect(position.toQuery()).toEqual({ cursor: '7', rosterCursor: '3', roster: `${SEAT_A}:4,${SEAT_B}:0` })

    const restored = new BpsPosition(OWNER, {
      cursor: 7n,
      rosterCursor: 3n,
      roster: { [`0x${SEAT_A}`]: 4n, [SEAT_B]: 0n },
    })
    expect(restored.toQuery()).toEqual(position.toQuery())
    expect(restored.accept(data(SEAT_A, 3n))).toBe(false)
    expect(restored.accept(data(SEAT_B, 0n))).toBe(true)
  })
})
