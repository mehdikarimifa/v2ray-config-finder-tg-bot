export interface IGeoInfo {
  countryCode: string
  countryName: string
}

export interface IVmessDetails {
  ps: string
  add: string
  port: number
  id: string
  aid: number
  scy: string
  net: string
  type: string // 'none' | 'http' | 'srtp' etc
  tls: string
  path?: string
  host?: string
  sni?: string
}

export interface IVlessDetails {
  ps: string
  add: string
  port: number
  id: string
  flow: string // 'xtls-rprx-vision' etc
  security: string // 'tls' | 'reality'
  path?: string
  host?: string
  sni?: string
  type: string // network type (tcp/ws/grpc)
  pbk?: string // Reality Public Key
  sid?: string // Reality Short ID
  fp?: string // Fingerprint
}

export interface ITrojanDetails {
  ps: string
  add: string
  port: number
  id: string // Password
  security: string
  sni?: string
  path?: string
  host?: string
}

export interface IShadowsocksDetails {
  ps: string
  add: string
  port: number
  method: string
  password: string
}

export interface IHysteria2Details {
  ps: string
  add: string
  port: number
  id: string // Password
  sni?: string
  insecure: boolean
}

// Union Config Type
export type ConfigDetails =
  | IVmessDetails
  | IVlessDetails
  | ITrojanDetails
  | IShadowsocksDetails
  | IHysteria2Details

export interface IParsedConfig {
  protocol: 'vmess' | 'vless' | 'trojan' | 'ss' | 'hysteria2'
  details: ConfigDetails
  originalLink: string
}

export interface ITestResult extends IGeoInfo {
  config: string
  name: string
  latency: number | null
  speedMbps: string | null
  tags: string[]
  tested_at: string
}
