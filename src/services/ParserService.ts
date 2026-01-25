import { IParsedConfig } from '@/types/index.js'

export class ParserService {
  static parseConfigsFromText(text: string): string[] {
    const lines = text.split('\n')
    const protocols = ['vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://']
    const configs = new Set<string>()

    for (const line of lines) {
      const trimmed = line.trim()
      if (protocols.some(p => trimmed.startsWith(p))) {
        configs.add(trimmed)
      }
    }
    return Array.from(configs)
  }

  static parseLink(link: string): IParsedConfig | null {
    const hashIndex = link.indexOf('#')
    const configPart = hashIndex === -1 ? link : link.substring(0, hashIndex)
    const protocolStr = configPart.split('://')[0]

    // Safety check for valid protocol
    if (!['vmess', 'vless', 'trojan', 'ss', 'hysteria2'].includes(protocolStr)) return null
    const protocol = protocolStr as IParsedConfig['protocol']

    try {
      let details: any = {}

      switch (protocol) {
        case 'vmess':
          details = JSON.parse(Buffer.from(configPart.substring(8), 'base64').toString())
          break

        case 'vless':
        case 'trojan': {
          const url = new URL(configPart)
          details = {
            id: url.username,
            add: url.hostname,
            port: parseInt(url.port)
          }
          url.searchParams.forEach((value, key) => {
            details[key] = value
          })
          break
        }

        case 'ss': {
          const url = new URL(configPart)
          const userInfo = Buffer.from(url.username, 'base64').toString()
          const [method, password] = userInfo.split(':')
          details = { method, password, add: url.hostname, port: parseInt(url.port) }
          break
        }

        case 'hysteria2': {
          const url = new URL(configPart)
          details = {
            id: url.username,
            add: url.hostname,
            port: parseInt(url.port),
            sni: url.searchParams.get('sni') || undefined,
            insecure: url.searchParams.get('insecure') === '1'
          }
          break
        }
      }

      // Ensure required fields exist
      if (!details.add || !details.port) return null

      // Handle Remarks
      const namePart = hashIndex === -1 ? '' : decodeURIComponent(link.substring(hashIndex + 1))
      details.ps = namePart || details.ps || `${details.add}:${details.port}`

      return { protocol, details, originalLink: link } as IParsedConfig
    } catch (e) {
      return null
    }
  }
}
