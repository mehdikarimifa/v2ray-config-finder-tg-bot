import { IParsedConfig } from '@/types/index.js'

export class ConfigBuilder {
  static build(config: IParsedConfig, localPort: number): any | null {
    const { protocol, details } = config
    let outboundConfig = null

    try {
      switch (protocol) {
        case 'vmess':
          outboundConfig = {
            protocol,
            settings: {
              vnext: [
                {
                  address: details.add,
                  port: details.port,
                  users: [
                    {
                      id: details.id,
                      alterId: details.aid || 0,
                      security: details.scy || 'auto'
                    }
                  ]
                }
              ]
            },
            streamSettings: {
              network: details.net,
              security: details.tls,
              wsSettings: { path: details.path, headers: { Host: details.host } },
              tlsSettings: { serverName: details.sni || details.host }
            }
          }
          break

        case 'vless':
          outboundConfig = {
            protocol,
            settings: {
              vnext: [
                {
                  address: details.add,
                  port: details.port,
                  users: [{ id: details.id, flow: details.flow, encryption: 'none' }]
                }
              ]
            },
            streamSettings: {
              network: details.type, // 'type' maps to network in vless URLs usually
              security: details.security,
              realitySettings:
                details.security === 'reality'
                  ? {
                      publicKey: details.pbk,
                      shortId: details.sid,
                      fingerprint: details.fp || 'chrome'
                    }
                  : undefined,
              wsSettings: { path: details.path, headers: { Host: details.host } },
              tlsSettings: { serverName: details.sni }
            }
          }
          break

        case 'trojan':
          outboundConfig = {
            protocol,
            settings: {
              servers: [
                {
                  address: details.add,
                  port: details.port,
                  password: details.id
                }
              ]
            },
            streamSettings: {
              security: details.security || 'tls',
              tlsSettings: { serverName: details.sni },
              wsSettings: { path: details.path, headers: { Host: details.host } }
            }
          }
          break

        case 'ss':
          outboundConfig = {
            protocol: 'shadowsocks',
            settings: {
              servers: [
                {
                  address: details.add,
                  port: details.port,
                  method: details.method,
                  password: details.password
                }
              ]
            }
          }
          break

        case 'hysteria2':
          outboundConfig = {
            protocol,
            settings: {
              servers: [
                {
                  address: details.add,
                  port: details.port,
                  password: details.id
                }
              ]
            },
            streamSettings: {
              network: 'udp',
              security: 'tls',
              tlsSettings: {
                serverName: details.sni,
                insecure: details.insecure,
                alpn: ['h3']
              }
            }
          }
          break
      }

      if (!outboundConfig) return null

      return {
        log: { loglevel: 'none' },
        inbounds: [{ port: localPort, listen: '127.0.0.1', protocol: 'socks' }],
        outbounds: [outboundConfig]
      }
    } catch (e) {
      return null
    }
  }
}
