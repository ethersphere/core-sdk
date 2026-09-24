import { describe, expect, it } from 'vitest'
import { uint64ToNumber, uint8ArrayToHex } from '../../src/bytes/encoding.js'
import { ChunkBuilder } from '../../src/chunk/splitter.js'
import { MantarayNode } from '../../src/mantaray/node.js'

const reference = (value: number, length = 32) => new Uint8Array(length).fill(value)
const hex = uint8ArrayToHex

// Stores the plaintext chunk under its address (the encrypted address when there is a key), so
// encrypted tries can be read back without decrypting. A node's selfAddress is address || key
// when encrypted, so only its first 32 bytes are used to look it up.
function makeStore() {
  const chunks = new Map<string, Uint8Array>()

  return {
    onChunk: async (chunk: ChunkBuilder, key?: Uint8Array) => {
      const address = key ? chunk.encryptedHash(key).address : chunk.hash()
      chunks.set(address.toHex(), chunk.build())
    },
    // Every manifest node in these tests fits in one chunk, so its body is span || data.
    load(selfAddress: Uint8Array): MantarayNode {
      const body = chunks.get(hex(selfAddress.subarray(0, 32)))
      if (!body) {
        throw new Error(`chunk ${hex(selfAddress.subarray(0, 32))} was never uploaded`)
      }
      const span = Number(uint64ToNumber(body.subarray(0, 8), 'LE'))

      return MantarayNode.unmarshalFromData(body.subarray(8, 8 + span), selfAddress)
    },
  }
}

type Store = ReturnType<typeof makeStore>

/** Loads the whole trie at `selfAddress`, putting every loaded child in place of its stub. */
function loadFully(store: Store, selfAddress: Uint8Array): MantarayNode {
  const node = store.load(selfAddress)
  for (const fork of node.forks.values()) {
    const child = loadFully(store, fork.node.selfAddress!)
    child.path = fork.prefix
    child.type = fork.node.type
    child.metadata = fork.node.metadata
    child.parent = node
    fork.node = child
  }

  return node
}

/** Every path with an entry in the stored trie at `root`, mapped to its target address as hex. */
function readEntries(store: Store, root: Uint8Array): Map<string, string> {
  const entries = new Map<string, string>()
  const walk = (node: MantarayNode, prefix: string) => {
    for (const fork of node.forks.values()) {
      const path = prefix + new TextDecoder().decode(fork.prefix)
      const child = store.load(fork.node.selfAddress!)
      if (child.targetAddress.some(byte => byte !== 0)) {
        entries.set(path, hex(child.targetAddress))
      }
      walk(child, path)
    }
  }
  walk(store.load(root), '')

  return entries
}

function build(paths: [string, number][]): MantarayNode {
  const root = new MantarayNode()
  for (const [path, value] of paths) {
    root.addFork(path, reference(value))
  }

  return root
}

const entriesOf = (paths: [string, number][]) => new Map(paths.map(([path, value]) => [path, hex(reference(value))]))

describe('saveRecursively after an address was only calculated', () => {
  // marshal() stores each child's calculated address on the child, and saveRecursively now
  // skips any child with an address, so a child that was hashed but never uploaded is skipped.

  it('uploads every node of a new tree after calculateSelfAddress', async () => {
    const paths: [string, number][] = [
      ['a.txt', 1],
      ['b.txt', 2],
    ]
    const root = build(paths)
    await root.calculateSelfAddress()

    const store = makeStore()
    const { reference: saved } = await root.saveRecursively(store.onChunk)

    expect(readEntries(store, saved)).toEqual(entriesOf(paths))
  })

  it('uploads the edited path of a saved tree after calculateSelfAddress', async () => {
    const paths: [string, number][] = [
      ['a/b/c', 1],
      ['a/b/x', 2],
      ['a/y', 3],
    ]
    const root = build(paths)
    const store = makeStore()
    await root.saveRecursively(store.onChunk)

    root.addFork('a/b/d', reference(4))
    await root.calculateSelfAddress()
    const { reference: resaved } = await root.saveRecursively(store.onChunk)

    expect(readEntries(store, resaved)).toEqual(entriesOf([...paths, ['a/b/d', 4]]))
  })
})

describe('editing a loaded encrypted manifest', () => {
  // unmarshalFromData never sets `encrypt`, so a loaded encrypted trie is edited and saved as
  // an unencrypted one.

  it('saves it encrypted, with one reference width', async () => {
    const store = makeStore()
    const root = new MantarayNode({ encrypt: true })
    root.addFork('a.txt', reference(1, 64))
    root.addFork('b.txt', reference(2, 64))
    const { reference: saved } = await root.saveRecursively(store.onChunk)

    const loaded = loadFully(store, saved)
    loaded.addFork('c.txt', reference(3, 64))
    const { reference: resaved } = await loaded.saveRecursively(store.onChunk)

    // Today the root is saved unencrypted (32-byte reference), and it holds the 64-byte
    // addresses of a.txt and b.txt next to the 32-byte address of the new, unencrypted c.txt.
    expect(resaved.length).toBe(64)
    for (const fork of loaded.forks.values()) {
      expect(fork.node.selfAddress!.length).toBe(64)
    }
  })
})

describe('removeFork merging a single child into its parent', () => {
  // The merged child keeps the type byte it was loaded with, although its path changed. Here the
  // merged prefix gains a path separator, so the stored type loses TYPE_WITH_PATH_SEPARATOR.

  it('writes the same fork type as a tree built with the merged path', async () => {
    const store = makeStore()
    const { reference: saved } = await build([
      ['x', 1],
      ['x/y', 2],
    ]).saveRecursively(store.onChunk)

    const loaded = loadFully(store, saved)
    loaded.removeFork('x')
    const { reference: resaved } = await loaded.saveRecursively(store.onChunk)

    const { reference: fresh } = await build([['x/y', 2]]).saveRecursively(store.onChunk)
    const typeOf = (root: Uint8Array) => store.load(root).forks.get('x'.charCodeAt(0))!.node.type

    expect(readEntries(store, resaved)).toEqual(entriesOf([['x/y', 2]]))
    expect(typeOf(resaved)).toBe(typeOf(fresh))
  })
})

describe('Fork.split after loading', () => {
  const forkTypeAt = (store: Store, root: Uint8Array, first: string, second: string) => {
    const parent = store.load(store.load(root).forks.get(first.charCodeAt(0))!.node.selfAddress!)

    return parent.forks.get(second.charCodeAt(0))!.node.type
  }

  it('writes the same fork type as a tree built with both paths', async () => {
    const store = makeStore()
    const { reference: saved } = await build([['x/y', 1]]).saveRecursively(store.onChunk)

    const loaded = loadFully(store, saved)
    loaded.addFork('x/z', reference(2))
    const { reference: resaved } = await loaded.saveRecursively(store.onChunk)

    const { reference: fresh } = await build([
      ['x/y', 1],
      ['x/z', 2],
    ]).saveRecursively(store.onChunk)

    expect(forkTypeAt(store, resaved, 'x', 'y')).toBe(forkTypeAt(store, fresh, 'x', 'y'))
  })
})

describe('editing a loaded encrypted manifest with a metadata-only node', () => {
  it('keeps one reference width across the saved root', async () => {
    const store = makeStore()
    const root = new MantarayNode({ encrypt: true })
    root.addFork('index.html', reference(1, 64))
    root.addFork('/', reference(0, 64), { 'website-index-document': 'index.html' })
    const { reference: saved } = await root.saveRecursively(store.onChunk)

    const loaded = loadFully(store, saved)
    loaded.addFork('/', reference(0, 64), { 'website-index-document': 'other.html' })
    const { reference: resaved } = await loaded.saveRecursively(store.onChunk)

    for (const fork of store.load(resaved).forks.values()) {
      expect(fork.node.selfAddress!.length).toBe(64)
    }
  })
})

describe('editing a node whose forks were never loaded', () => {
  async function savedRoot(store: Store): Promise<Uint8Array> {
    const { reference: saved } = await build([
      ['dir/a.txt', 1],
      ['dir/b.txt', 2],
      ['solo.txt', 3],
    ]).saveRecursively(store.onChunk)

    return saved
  }

  it('refuses to add a fork under it', async () => {
    const store = makeStore()
    const root = store.load(await savedRoot(store))

    expect(() => root.addFork('dir/c.txt', reference(4))).toThrow(/not loaded/)
  })

  it('refuses to remove it', async () => {
    const store = makeStore()
    const root = store.load(await savedRoot(store))

    expect(() => root.removeFork('dir/')).toThrow(/not loaded/)
  })

  it('still allows editing a loaded subtree', async () => {
    const store = makeStore()
    const root = loadFully(store, await savedRoot(store))
    root.addFork('dir/c.txt', reference(4))
    const { reference: resaved } = await root.saveRecursively(store.onChunk)

    expect(readEntries(store, resaved)).toEqual(
      entriesOf([
        ['dir/a.txt', 1],
        ['dir/b.txt', 2],
        ['solo.txt', 3],
        ['dir/c.txt', 4],
      ]),
    )
  })

  it('refuses to add a fork under an unloaded leaf', async () => {
    const store = makeStore()
    const root = store.load(await savedRoot(store))

    expect(() => root.addFork('solo.txt.bak', reference(5))).toThrow(/not loaded/)
  })

  it('keeps the stored type of an unloaded node moved by a split', async () => {
    const store = makeStore()
    const { reference: saved } = await build([
      ['dir/one', 1],
      ['dir/two', 2],
    ]).saveRecursively(store.onChunk)

    const root = store.load(saved)
    root.addFork('dir2', reference(3))
    const { reference: resaved } = await root.saveRecursively(store.onChunk)

    const { reference: fresh } = await build([
      ['dir/one', 1],
      ['dir/two', 2],
      ['dir2', 3],
    ]).saveRecursively(store.onChunk)
    const slashTypeOf = (saved: Uint8Array) => {
      const dir = store.load(store.load(saved).forks.get('d'.charCodeAt(0))!.node.selfAddress!)

      return dir.forks.get('/'.charCodeAt(0))!.node.type
    }

    expect(readEntries(store, resaved)).toEqual(
      entriesOf([
        ['dir/one', 1],
        ['dir/two', 2],
        ['dir2', 3],
      ]),
    )
    expect(slashTypeOf(resaved)).toBe(slashTypeOf(fresh))
  })
})
