import { readFile } from 'node:fs/promises'
import { Server } from '@modelcontextprotocol/sdk/server/index.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { ListToolsRequestSchema, CallToolRequestSchema } from '@modelcontextprotocol/sdk/types.js'
const parameters = { type: 'object', properties: { file: { type: 'string', enum: ['note.txt','proof.txt'] } }, required: ['file'], additionalProperties: false }
const server = new Server({ name: 'j-bridge-fixture', version: '1.0.0' }, { capabilities: { tools: {} } })
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: [{ name: 'read_fixture', inputSchema: parameters }] }))
server.setRequestHandler(CallToolRequestSchema, async request => {
  if (request.params.name !== 'read_fixture' || !['note.txt','proof.txt'].includes(request.params.arguments?.file)) throw Error('denied')
  return { content: [{ type: 'text', text: await readFile(request.params.arguments.file, 'utf8') }] }
})
await server.connect(new StdioServerTransport())
