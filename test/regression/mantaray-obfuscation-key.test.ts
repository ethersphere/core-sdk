import { describe, expect, it } from 'vitest'
import { equals } from '../../src/bytes/encoding.js'
import { MantarayNode } from '../../src/mantaray/node.js'

// Regression: https://github.com/ethersphere/core-sdk/issues/8
const INDEX_METADATA = { 'website-index-document': 'index.html' }

function manifest(fileReference: number): MantarayNode {
  const root = new MantarayNode()
  root.addFork('/', new Uint8Array(32), INDEX_METADATA)
  root.addFork('index.html', new Uint8Array(32).fill(fileReference))

  return root
}

describe('MantarayNode obfuscation key', () => {
  it('is random for a fresh node', () => {
    const node = new MantarayNode()

    expect(equals(node.obfuscationKey, new Uint8Array(32))).toBe(false)
    expect(equals(node.obfuscationKey, new MantarayNode().obfuscationKey)).toBe(false)
  })

  it('gives the metadata-only "/" node a distinct address per manifest', async () => {
    const a = await manifest(1).find('/')!.calculateSelfAddress()
    const b = await manifest(2).find('/')!.calculateSelfAddress()

    expect(a.toHex()).not.toBe(b.toHex())
  })

  it('is stored in the clear, so a randomized node still round-trips', async () => {
    const node = manifest(3)
    const restored = MantarayNode.unmarshalFromData(await node.marshal())

    expect(restored.obfuscationKey).toEqual(node.obfuscationKey)
    expect(restored.forks.size).toBe(node.forks.size)
    expect(await restored.marshal()).toEqual(await node.marshal())
  })
})
