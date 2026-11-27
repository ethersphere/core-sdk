import { bench } from 'vitest'
import { stamp, Stamper } from '../src/stamper/stamper.js'

const SIGNER = new Uint8Array(32).fill(0x11)
const BATCH_ID = new Uint8Array(32).fill(0x22)
const ADDRESS = new Uint8Array(32).fill(0x33)
const stamper = Stamper.fromBlank(SIGNER, BATCH_ID, 24)

bench('stamp() one chunk address', () => {
  stamp(SIGNER, BATCH_ID, ADDRESS, 0, 1_700_000_000_000)
})

let counter = 0

bench('Stamper#stamp one chunk address', () => {
  const address = ADDRESS.slice()
  address[0] = counter & 0xff
  address[1] = (counter++ >> 8) & 0xff
  stamper.stamp(address, 1_700_000_000_000)
})
