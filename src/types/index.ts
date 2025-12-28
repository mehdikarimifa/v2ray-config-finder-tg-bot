export interface IGeoInfo {
  countryCode: string
  countryName: string
}

export interface IV2RayConfigDetails {
  ps?: string
  add: string
  port: number
  id?: string
  net?: string
  type?: string
  tls?: string
  path?: string
  host?: string
  sni?: string
  scy?: string
  aid?: number
  flow?: string
  security?: string
  pbk?: string // Public Key (Reality)
  sid?: string // Short ID (Reality)
  fp?: string // Fingerprint
  method?: string // Shadowsocks
  password?: string // Shadowsocks/Trojan
  insecure?: boolean
}

export interface IParsedConfig {
  protocol: 'vmess' | 'vless' | 'trojan' | 'ss' | 'hysteria2'
  details: IV2RayConfigDetails
  originalLink: string
}

export interface ITestResult extends IGeoInfo {
  config: string // The full link
  name: string
  latency: number | null // null = failed
  speedMbps: string | null
  tags: string[]
  tested_at: string
}
