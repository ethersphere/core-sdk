import { build } from 'esbuild'
import { getEntryPoints, getSkippedEntryPoints } from './entry-points.mjs'

const entryPoints = getEntryPoints()
const skipped = getSkippedEntryPoints()
if (skipped.length > 0) {
    console.log(`Skipping not-yet-implemented entry points: ${skipped.join(', ')}`)
}

if (entryPoints.length === 0) {
    console.log('No entry points implemented yet - nothing to build.')
    process.exit(0)
}

const shared = {
    entryPoints,
    bundle: true,
    outbase: 'src',
    outdir: 'dist',
    target: 'es2022',
    sourcemap: true,
    external: ['@noble/curves', '@noble/curves/*']
}

await build({ ...shared, format: 'esm', platform: 'neutral' })
await build({ ...shared, format: 'cjs', platform: 'node', outExtension: { '.js': '.cjs' } })
