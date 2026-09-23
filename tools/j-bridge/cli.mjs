import { readFile } from 'node:fs/promises'
import { createInterface } from 'node:readline/promises'
import { apiClient, runBridge } from './bridge.mjs'

const [manifestPath, session] = process.argv.slice(2)
if (!manifestPath || !session || !process.env.SUB2API_API_KEY || !process.env.SUB2API_BASE_URL) {
  console.error('Usage: SUB2API_BASE_URL=https://your-gateway SUB2API_API_KEY=... node cli.mjs manifest.json session-id')
  process.exit(2)
}
const controller = new AbortController()
for (const event of ['SIGINT', 'SIGTERM']) process.on(event, () => controller.abort())
try {
  const raw = await readFile(manifestPath)
  if (raw.length > 256 * 1024) throw Error('manifest_too_large')
  await runBridge({ manifest: JSON.parse(raw), session, api: apiClient(process.env.SUB2API_BASE_URL, process.env.SUB2API_API_KEY), signal: controller.signal,
    ready: info => console.log(JSON.stringify(info)), // Grant secret never leaves this process.
    approve: async ({ tool, arguments: args, callID, signal }) => {
      if (!process.stdin.isTTY) return false
      const terminal = createInterface({ input: process.stdin, output: process.stderr })
      try {
        const answer = await terminal.question(`Authorize ${tool}: ${JSON.stringify(args)}\nType ${callID} to execute: `, { signal })
        return answer === callID
      } finally { terminal.close() }
    }
  })
} catch {
  if (!controller.signal.aborted) { console.error('Bridge stopped. No failed or uncertain tool call was retried.'); process.exitCode = 1 }
}
