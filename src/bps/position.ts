import { Bytes } from '../bytes/bytes.js'
import { EthAddress } from '../bytes/eth-address.js'
import { BpsKind } from './chunk.js'
import { decodeBpsRoster } from './roster.js'

export interface BpsPositionOptions {
  cursor?: bigint
  roster?: Record<string, bigint>
  rosterCursor?: bigint
  ended?: boolean
}

export class BpsPosition {
  private readonly owner: string
  private readonly cursors = new Map<string, bigint>()
  private publishers: string[] = []
  private nextRosterIndex: bigint
  private channelEnded: boolean

  constructor(owner: EthAddress | Uint8Array | string, options: BpsPositionOptions = {}) {
    this.owner = new EthAddress(owner).toHex()
    this.cursors.set(this.owner, options.cursor ?? 0n)

    for (const [address, cursor] of Object.entries(options.roster ?? {})) {
      const publisher = new EthAddress(address).toHex()
      this.publishers.push(publisher)
      this.cursors.set(publisher, cursor)
    }

    this.nextRosterIndex = options.rosterCursor ?? 0n
    this.channelEnded = options.ended ?? false
  }

  get ended(): boolean {
    return this.channelEnded
  }

  get roster(): EthAddress[] {
    return this.publishers.map(publisher => new EthAddress(publisher))
  }

  get rosterCursor(): bigint {
    return this.nextRosterIndex
  }

  cursor(publisher: EthAddress | Uint8Array | string = this.owner): bigint {
    return this.cursors.get(new EthAddress(publisher).toHex()) ?? 0n
  }

  accept(delivery: {
    kind: BpsKind
    owner: EthAddress | Uint8Array | string
    index: bigint
    payload: Bytes | Uint8Array
  }): boolean {
    switch (delivery.kind) {
      case BpsKind.Data: {
        const publisher = new EthAddress(delivery.owner).toHex()

        if (!this.admits(publisher) || delivery.index < this.cursor(publisher)) {
          return false
        }
        this.cursors.set(publisher, delivery.index + 1n)

        return true
      }
      case BpsKind.Roster:
        if (delivery.index < this.nextRosterIndex) {
          return false
        }
        this.publishers = decodeBpsRoster(delivery.payload).map(publisher => publisher.toHex())
        this.nextRosterIndex = delivery.index + 1n

        return true
      case BpsKind.Eos:
        if (this.channelEnded) {
          return false
        }
        this.channelEnded = true

        return true
      default:
        return false
    }
  }

  toQuery(): Record<string, string> {
    const query: Record<string, string> = {
      cursor: this.cursor().toString(),
      rosterCursor: this.nextRosterIndex.toString(),
    }

    if (this.publishers.length > 0) {
      query.roster = this.publishers.map(publisher => `${publisher}:${this.cursor(publisher)}`).join(',')
    }

    return query
  }

  private admits(publisher: string): boolean {
    return publisher === this.owner || this.publishers.includes(publisher)
  }
}
