import { describe, expect, it } from 'vitest'
import { parseClashProxyConfig } from '@/utils/clashProxyParser'

describe('parseClashProxyConfig', () => {
  it('parses supported Clash nodes and removes duplicates', () => {
    const result = parseClashProxyConfig(`proxies:
  - name: office
    type: http
    server: proxy.example.com
    port: 8080
  - name: duplicate
    type: http
    server: proxy.example.com
    port: 8080
  - name: ipv6
    type: socks5
    server: "[2001:db8::1]"
    port: 1080`)

    expect(result.candidates).toHaveLength(2)
    expect(result.candidates[0]).toMatchObject({ name: 'office', protocol: 'http', host: 'proxy.example.com', port: 8080 })
    expect(result.candidates[1]).toMatchObject({ protocol: 'socks5', host: '2001:db8::1', port: 1080 })
  })

  it('keeps unsupported transports out of import candidates', () => {
    const result = parseClashProxyConfig(JSON.stringify({ proxies: [
      { name: 'secure', type: 'ss', server: 'proxy.example.com', port: 443 },
      { name: 'valid', type: 'https', server: 'proxy.example.com', port: 443 },
    ] }))

    expect(result.candidates).toHaveLength(1)
    expect(result.unsupported).toMatchObject([{ name: 'secure', type: 'ss' }])
  })

  it('does not abort URL imports on malformed percent encoding', () => {
    const result = parseClashProxyConfig('http://bad%zz:pass@proxy.example.com:8080\nhttp://proxy.example.com:8081')
    expect(result.candidates).toHaveLength(2)
    expect(result.candidates[0].username).toBe('bad%zz')
  })
})
