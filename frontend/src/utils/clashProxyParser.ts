import type { ProxyProtocol } from '@/types'

export interface ClashProxyCandidate {
  name?: string
  protocol: ProxyProtocol
  host: string
  port: number
  username: string
  password: string
}

export interface ClashProxyParseResult {
  candidates: ClashProxyCandidate[]
  unsupported: Array<{ name?: string; type?: string; reason: string }>
  invalid: Array<{ name?: string; reason: string }>
}

const supportedTypes = new Set(['http', 'https', 'socks5', 'socks5h'])

const unquote = (value: string): string => {
  const trimmed = value.trim()
  if ((trimmed.startsWith('"') && trimmed.endsWith('"')) || (trimmed.startsWith("'") && trimmed.endsWith("'"))) {
    return trimmed.slice(1, -1)
  }
  return trimmed
}

const stripYamlComment = (value: string): string => {
  let quoted = false
  let quote = ''
  for (let i = 0; i < value.length; i += 1) {
    const char = value[i]
    if ((char === '"' || char === "'") && (!i || value[i - 1] !== '\\')) {
      if (!quoted) {
        quoted = true
        quote = char
      } else if (quote === char) {
        quoted = false
      }
    }
    if (!quoted && char === '#' && (i === 0 || /\s/.test(value[i - 1]))) {
      return value.slice(0, i).trim()
    }
  }
  return value.trim()
}

const safeDecode = (value: string): string => {
  try {
    return decodeURIComponent(value)
  } catch {
    return value
  }
}

const parseProxyUrl = (raw: string): ClashProxyCandidate | null => {
  const value = raw.trim()
  const match = value.match(/^(https?|socks5h?):\/\/(?:([^:@\[\]]+):([^@\[\]]+)@)?(\[[0-9a-f:.]+\]|[^:\[\]]+):(\d+)$/i)
  if (!match) return null
  const [, protocol, username, password, rawHost, port] = match
  const portNumber = Number(port)
  if (!Number.isInteger(portNumber) || portNumber < 1 || portNumber > 65535) return null
  return {
    protocol: protocol.toLowerCase() as ProxyProtocol,
    host: rawHost.replace(/^\[|\]$/g, '').trim(),
    port: portNumber,
    username: username ? safeDecode(username) : '',
    password: password ? safeDecode(password) : ''
  }
}

const parseJson = (value: unknown): Array<Record<string, unknown>> | null => {
  if (Array.isArray(value)) return value.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
  if (!value || typeof value !== 'object') return null
  const root = value as Record<string, unknown>
  if (Array.isArray(root.proxies)) {
    return root.proxies.filter((item): item is Record<string, unknown> => !!item && typeof item === 'object')
  }
  return null
}

const normalizeObject = (item: Record<string, unknown>, index: number, result: ClashProxyParseResult) => {
  const name = typeof item.name === 'string' ? item.name : undefined
  const rawType = typeof item.type === 'string' ? item.type.toLowerCase() : ''
  if (!supportedTypes.has(rawType)) {
    result.unsupported.push({ name, type: rawType || undefined, reason: rawType ? `协议 ${rawType} 不能直接映射为 Sub2API 代理` : '缺少 type 字段' })
    return
  }
  const host = typeof item.server === 'string' ? item.server.trim().replace(/^\[|\]$/g, '') : ''
  const port = Number(item.port)
  if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
    result.invalid.push({ name, reason: `第 ${index + 1} 个节点缺少有效 server/port` })
    return
  }
  result.candidates.push({
    name,
    protocol: rawType as ProxyProtocol,
    host,
    port,
    username: typeof item.username === 'string' ? item.username : '',
    password: typeof item.password === 'string' ? item.password : ''
  })
}

const parseYamlObjects = (text: string): Array<Record<string, unknown>> => {
  const objects: Array<Record<string, unknown>> = []
  let current: Record<string, unknown> | null = null
  let inProxies = false
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.replace(/\t/g, '    ')
    if (/^\s*proxies\s*:\s*(?:#.*)?$/.test(line)) {
      inProxies = true
      continue
    }
    if (!inProxies || /^\S/.test(line) && !/^\s*-/.test(line)) {
      if (/^\S/.test(line) && !/^\s*proxies\s*:/.test(line)) inProxies = false
      continue
    }
    const listMatch = line.match(/^\s*-\s*([^:]+):\s*(.*)$/)
    if (listMatch) {
      if (current) objects.push(current)
      current = {}
      current[listMatch[1].trim()] = unquote(stripYamlComment(listMatch[2]))
      continue
    }
    const fieldMatch = line.match(/^\s{2,}([^:#][^:]*):\s*(.*)$/)
    if (fieldMatch && current) {
      const key = fieldMatch[1].trim()
      const rawValue = unquote(stripYamlComment(fieldMatch[2]))
      current[key] = /^\d+$/.test(rawValue) ? Number(rawValue) : rawValue
    }
  }
  if (current) objects.push(current)
  return objects
}

export const parseClashProxyConfig = (text: string): ClashProxyParseResult => {
  const result: ClashProxyParseResult = { candidates: [], unsupported: [], invalid: [] }
  const trimmed = text.trim()
  if (!trimmed) return result

  try {
    const json = parseJson(JSON.parse(trimmed))
    if (json) {
      json.forEach((item, index) => normalizeObject(item, index, result))
      deduplicate(result)
      return result
    }
  } catch {
    // Fall through to the YAML reader.
  }

  const yamlObjects = parseYamlObjects(trimmed)
  if (yamlObjects.length > 0) {
    yamlObjects.forEach((item, index) => normalizeObject(item, index, result))
    deduplicate(result)
    return result
  }

  for (const [index, line] of trimmed.split(/\r?\n/).entries()) {
    const parsed = parseProxyUrl(line)
    if (parsed) result.candidates.push(parsed)
    else if (line.trim()) result.invalid.push({ reason: `第 ${index + 1} 行不是受支持的代理 URL` })
  }
  deduplicate(result)
  return result
}

function deduplicate(result: ClashProxyParseResult) {
  const seen = new Set<string>()
  result.candidates = result.candidates.filter((item) => {
    const key = [item.protocol, item.host.toLowerCase(), item.port, item.username, item.password].join('|')
    if (seen.has(key)) return false
    seen.add(key)
    return true
  })
}
