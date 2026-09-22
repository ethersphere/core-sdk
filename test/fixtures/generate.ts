import { open, stat } from 'node:fs/promises'
import { dirname, join } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const DIRECTORY = dirname(fileURLToPath(import.meta.url))

// Sizes just past a level-2 node boundary (64 MiB plain, 16 MiB encrypted), plus a single-level control.
export const FIXTURES = {
  'splitter-data-loss-67600000.bin': 67_600_000,
  'splitter-data-loss-encrypted-16850000.bin': 16_850_000,
  'small.bin': 100_000,
}

// Unique content per chunk: with repeating data a dropped chunk is identical to a kept one and the loss hides.
async function generate(path: string, size: number): Promise<void> {
  let state = 0x9e3779b9
  const block = Buffer.alloc(1 << 20)
  const file = await open(path, 'w')

  for (let written = 0; written < size; written += block.length) {
    for (let i = 0; i < block.length; i += 4) {
      state ^= state << 13
      state ^= state >>> 17
      state ^= state << 5
      block.writeUInt32LE(state >>> 0, i)
    }
    await file.write(block, 0, Math.min(block.length, size - written))
  }

  await file.close()
}

export async function fixture(name: keyof typeof FIXTURES): Promise<string> {
  const path = join(DIRECTORY, name)
  const size = FIXTURES[name]
  const existing = await stat(path).catch(() => undefined)

  if (existing?.size !== size) {
    await generate(path, size)
  }

  return path
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  for (const name of Object.keys(FIXTURES) as (keyof typeof FIXTURES)[]) {
    console.log(await fixture(name))
  }
}
