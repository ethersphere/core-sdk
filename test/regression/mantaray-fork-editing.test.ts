import { describe, expect, it } from 'vitest'
import { uint8ArrayToHex } from '../../src/bytes/encoding.js'
import { MantarayNode } from '../../src/mantaray/node.js'

const reference = (value: number) => new Uint8Array(32).fill(value)

describe('MantarayNode.addFork on an existing path', () => {
  it('overwrites the entry of a path that already has one', () => {
    const root = new MantarayNode()
    root.addFork('a', reference(1))
    root.addFork('a', reference(2))

    expect(root.find('a')!.targetAddress).toEqual(reference(2))
  })

  it('sets the entry on a bare node created by a fork split', () => {
    const root = new MantarayNode()
    root.addFork('ab', reference(1))
    root.addFork('ac', reference(2))
    root.addFork('a', reference(3))

    expect(root.find('a')!.targetAddress).toEqual(reference(3))
  })

  it('keeps metadata when overwriting an entry', () => {
    const root = new MantarayNode()
    root.addFork('a', reference(1), { 'Content-Type': 'text/plain' })
    root.addFork('a', reference(2), { 'Content-Type': 'application/json' })

    expect(root.find('a')!.metadata).toEqual({ 'Content-Type': 'application/json' })
  })
})

describe('MantarayNode.removeFork', () => {
  it('re-attaches the whole subtree of the removed node', () => {
    const root = new MantarayNode()
    root.addFork('a', reference(1))
    root.addFork('ab', reference(2))
    root.addFork('abc', reference(3))

    root.removeFork('a')

    expect(Object.keys(root.collectAndMap()).sort()).toEqual(['ab', 'abc'])
  })

  it('keeps every child when the removed node has more than one', () => {
    const root = new MantarayNode()
    root.addFork('a', reference(1))
    root.addFork('ab', reference(2))
    root.addFork('ac', reference(3))

    root.removeFork('a')

    expect(Object.keys(root.collectAndMap()).sort()).toEqual(['ab', 'ac'])
  })

  it('keeps the child when its merged prefix would exceed a fork prefix', () => {
    const base = 'x'.repeat(25)
    const root = new MantarayNode()
    root.addFork(base, reference(1))
    root.addFork(base + 'y'.repeat(10), reference(2))

    root.removeFork(base)

    expect(Object.keys(root.collectAndMap())).toEqual([base + 'y'.repeat(10)])
  })
})

describe('MantarayNode.saveRecursively', () => {
  it('leaves unloaded child nodes untouched', async () => {
    const root = new MantarayNode()
    root.addFork('dir/file.txt', reference(4))
    await root.saveRecursively(async () => {})

    const loaded = MantarayNode.unmarshalFromData(await root.marshal())
    const before = [...loaded.forks.values()].map(fork => uint8ArrayToHex(fork.node.selfAddress!))
    await loaded.saveRecursively(async () => {})
    const after = [...loaded.forks.values()].map(fork => uint8ArrayToHex(fork.node.selfAddress!))

    expect(after).toEqual(before)
  })
})

describe('MantarayNode self address invalidation', () => {
  async function savedTree(): Promise<MantarayNode> {
    const root = new MantarayNode()
    root.addFork('a/b/c', reference(1))
    root.addFork('a/z', reference(2))
    root.addFork('a/b/x', reference(3))
    await root.saveRecursively(async () => {})

    return root
  }

  it('changes the root address when a deep path is removed', async () => {
    const root = await savedTree()
    const before = (await root.calculateSelfAddress()).toHex()

    root.removeFork('a/b/x')

    expect((await root.calculateSelfAddress()).toHex()).not.toBe(before)
  })

  it('changes the root address when a deep path is edited', async () => {
    const root = new MantarayNode()
    root.addFork('a/b/c', reference(1))
    root.addFork('a/z', reference(2))
    root.addFork('a/b/x', reference(3))
    await root.saveRecursively(async () => {})
    const before = (await root.calculateSelfAddress()).toHex()

    root.addFork('a/b/y', reference(4))

    expect((await root.calculateSelfAddress()).toHex()).not.toBe(before)
  })
})
