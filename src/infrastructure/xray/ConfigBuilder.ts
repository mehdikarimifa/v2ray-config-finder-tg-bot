import {
  IParsedConfig,
  IVmessDetails,
  IVlessDetails,
  ITrojanDetails,
  IShadowsocksDetails,
  IHysteria2Details
} from '@/types/index.js'

export class ConfigBuilder {
  /**
   * Generates a single Xray config JSON for multiple proxies.
   * Maps local ports to specific proxy outbounds.
   */
  static buildBatch(items: { config: IParsedConfig; port: number; id: number }[]): any {
    const inbounds: any[] = []
    const outbounds: any[] = []
    const rules: any[] = []

    // 1. Add the "Direct" outbound (required for Xray to work properly)
    outbounds.push({ protocol: 'freedom', tag: 'direct' })

    for (const item of items) {
      const { config, port, id } = item
      const proxyTag = `proxy_${id}`
      const inboundTag = `in_${id}`

      // A. Build the Proxy Outbound
      const outbound = this.buildSingleOutbound(config)
      if (!outbound) continue // Skip invalid configs

      outbound.tag = proxyTag
      outbounds.push(outbound)

      // B. Build the SOCKS Inbound
      inbounds.push({
        tag: inboundTag,
        port: port,
        listen: '127.0.0.1',
        protocol: 'socks',
        settings: { udp: true }
      })

      // C. Add Routing Rule (Inbound -> Outbound)
      rules.push({
        type: 'field',
        inboundTag: [inboundTag],
        outboundTag: proxyTag
      })
    }

    if (outbounds.length <= 1) return null // Only 'direct' exists

    return {
      log: { loglevel: 'none' },
      inbounds,
      outbounds,
      routing: {
        domainStrategy: 'AsIs',
        rules
      }
    }
  }

  private static buildSingleOutbound(config: IParsedConfig): any | null {
    const { protocol, details } = config
    try {
      switch (protocol) {
        case 'vmess': {
          const d = details as IVmessDetails
          return {
            protocol,
            settings: {
              vnext: [
                {
                  address: d.add,
                  port: d.port,
                  users: [{ id: d.id, alterId: d.aid || 0, security: d.scy || 'auto' }]
                }
              ]
            },
            streamSettings: {
              network: d.net,
              security: d.tls,
              wsSettings: { path: d.path, headers: { Host: d.host } },
              tlsSettings: { serverName: d.sni || d.host }
            }
          }
        }
        case 'vless': {
          const d = details as IVlessDetails
          return {
            protocol,
            settings: {
              vnext: [
                {
                  address: d.add,
                  port: d.port,
                  users: [{ id: d.id, flow: d.flow, encryption: 'none' }]
                }
              ]
            },
            streamSettings: {
              network: d.type,
              security: d.security,
              realitySettings:
                d.security === 'reality'
                  ? {
                      publicKey: d.pbk,
                      shortId: d.sid,
                      fingerprint: d.fp || 'chrome'
                    }
                  : undefined,
              wsSettings: { path: d.path, headers: { Host: d.host } },
              tlsSettings: { serverName: d.sni }
            }
          }
        }
        case 'trojan': {
          const d = details as ITrojanDetails
          return {
            protocol,
            settings: {
              servers: [{ address: d.add, port: d.port, password: d.id }]
            },
            streamSettings: {
              security: d.security || 'tls',
              tlsSettings: { serverName: d.sni },
              wsSettings: { path: d.path, headers: { Host: d.host } }
            }
          }
        }
        case 'ss': {
          const d = details as IShadowsocksDetails
          return {
            protocol: 'shadowsocks',
            settings: {
              servers: [
                {
                  address: d.add,
                  port: d.port,
                  method: d.method,
                  password: d.password
                }
              ]
            }
          }
        }
        case 'hysteria2': {
          const d = details as IHysteria2Details
          return {
            protocol,
            settings: {
              servers: [{ address: d.add, port: d.port, password: d.id }]
            },
            streamSettings: {
              network: 'udp',
              security: 'tls',
              tlsSettings: {
                serverName: d.sni,
                insecure: d.insecure,
                alpn: ['h3']
              }
            }
          }
        }
      }
    } catch (e) {
      return null
    }
  }
}
