import axios from 'axios'
import { spawn } from 'child_process'
import crypto from 'crypto'
import 'dotenv/config'
import fs from 'fs/promises'
import path from 'path'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { all, initDb } from './database.js'

// --- Configuration ---
const MAX_LATENCY_MS = process.env.MAX_LATENCY_MS ? parseInt(process.env.MAX_LATENCY_MS, 10) : 1000
const CONCURRENT_TESTS = process.env.CONCURRENT_TESTS
  ? parseInt(process.env.CONCURRENT_TESTS, 10)
  : 10
const TEST_INTERVAL_MINUTES = process.env.TEST_INTERVAL_MINUTES
  ? parseInt(process.env.TEST_INTERVAL_MINUTES, 10)
  : 30
const ENABLE_SPEED_TEST = process.env.ENABLE_SPEED_TEST === 'true'
const SPEED_TEST_URL = process.env.SPEED_TEST_URL || 'http://cachefly.cachefly.net/5mb.test'
const SPEED_TEST_FILE_SIZE_MB = process.env.SPEED_TEST_FILE_SIZE_MB
  ? parseInt(process.env.SPEED_TEST_FILE_SIZE_MB, 10)
  : 5
const PROXY_URL = process.env.PROXY_URL

// --- Command-line argument parsing ---
const getArg = argName => {
  const argIndex = process.argv.indexOf(argName)
  return argIndex > -1 && process.argv.length > argIndex + 1 ? process.argv[argIndex + 1] : null
}

// --- Main Tester Logic ---
async function initialize() {
  const singleFilePath = getArg('--file')

  if (singleFilePath) {
    console.log(`[Tester] Starting in single-file mode for: ${singleFilePath}`)
    await runSingleFileTest(singleFilePath)
    process.exit(0)
  } else {
    console.log('[Tester] Starting in scheduled mode. Fetching configs from database.')
    await initDb()
    if (ENABLE_SPEED_TEST) console.log(`[Tester] Full Speed Testing is ENABLED.`)
    else console.log(`[Tester] Quick Latency Testing is ENABLED.`)

    runTestCycle()
    setInterval(runTestCycle, TEST_INTERVAL_MINUTES * 60 * 1000)
  }
}

// --- Helper Functions ---
async function getGeoInfo(ip) {
  if (
    !ip ||
    !/^\d{1,3}(\.\d{1,3}){3}$/.test(ip) ||
    ip.startsWith('192.168') ||
    ip.startsWith('10.') ||
    ip === '127.0.0.1'
  ) {
    return { countryCode: 'XX', countryName: 'Private/Invalid IP' }
  }
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}?fields=country,countryCode`)
    return {
      countryCode: response.data.countryCode || 'XX',
      countryName: response.data.country || 'Unknown'
    }
  } catch (error) {
    return { countryCode: 'XX', countryName: 'Error' }
  }
}

function parseConfigsFromText(text) {
  const lines = text.split('\n')
  const protocolsToTest = ['vmess://', 'vless://', 'trojan://', 'ss://', 'hysteria2://']
  const configs = new Set()
  for (const line of lines) {
    const trimmedLine = line.trim()
    if (protocolsToTest.some(p => trimmedLine.startsWith(p))) {
      configs.add(trimmedLine)
    }
  }
  return Array.from(configs)
}

function parseLink(link) {
  const hashIndex = link.indexOf('#')
  const configPart = hashIndex === -1 ? link : link.substring(0, hashIndex)
  const namePart = hashIndex === -1 ? '' : decodeURIComponent(link.substring(hashIndex + 1))
  const protocol = configPart.split('://')[0]

  try {
    let details = {}
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
        details = {
          method,
          password,
          add: url.hostname,
          port: parseInt(url.port)
        }
        break
      }
      case 'hysteria2': {
        const url = new URL(configPart)
        details = {
          id: url.username,
          add: url.hostname,
          port: parseInt(url.port),
          sni: url.searchParams.get('sni'),
          insecure: url.searchParams.get('insecure') === '1'
        }
        break
      }
      default:
        return null
    }
    details.ps = namePart || details.ps || `${details.add}:${details.port}`
    return { protocol, details }
  } catch (e) {
    return null
  }
}

async function testConfig(originalLink, testPort) {
  const parsed = parseLink(originalLink)
  if (!parsed || !parsed.details.add || !parsed.details.port) return null

  const { protocol, details } = parsed
  const tempConfigPath = `./tmp/test_config_${testPort}_${crypto
    .randomBytes(4)
    .toString('hex')}.json`
  let xrayProcess = null

  try {
    const xrayConfig = generateXrayConfig(protocol, details, testPort)
    if (!xrayConfig) return null

    await fs.writeFile(tempConfigPath, JSON.stringify(xrayConfig))
    xrayProcess = await startXrayProcess(tempConfigPath)

    const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${testPort}`)

    const latency = await measureStability(agent, MAX_LATENCY_MS)
    if (latency === null) {
      console.log(`❌ [FAILED] Stability Check Failed (Packet Loss) | ${details.ps}`)
      return null
    }

    let speedMbps = null
    if (ENABLE_SPEED_TEST) {
      speedMbps = await measureSpeed(agent)
    }

    const geo = await getGeoInfo(details.add)

    console.log(
      `✅ [SUCCESS] (TTFB: ${latency}ms) | Speed: ${speedMbps ? speedMbps + 'Mbps' : 'N/A'} | ${
        geo.countryName
      } | ${details.ps}`
    )

    return {
      config: originalLink,
      latency,
      speedMbps,
      ...geo,
      name: details.ps,
      tags: [],
      tested_at: new Date().toISOString()
    }
  } catch (error) {
    return null
  } finally {
    await cleanup(xrayProcess, tempConfigPath)
  }
}

/**
 * Helper: Generates the complex Xray JSON structure
 * Separates configuration logic from execution logic.
 */
function generateXrayConfig(protocol, details, localPort) {
  try {
    let outboundConfig = null

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
            network: details.type,
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

      default:
        return null
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

/**
 * Helper: Spawns the Xray process and waits for it to stabilize
 */
async function startXrayProcess(configPath) {
  const xray = spawn('./xray', ['-c', configPath])
  await new Promise(resolve => setTimeout(resolve, 500))
  return xray
}

/**
 * STRICT Stability Tester
 * - Runs 3 sequential pings.
 * - If ANY ping fails or times out, it returns NULL (fail).
 * - Returns the average latency only if connection is rock solid.
 */
async function measureStability(agent, maxTimeout = 1500) {
  const targetUrl = 'http://www.gstatic.com/generate_204'
  const sampleCount = 3
  const timings = []

  for (let i = 0; i < sampleCount; i++) {
    const start = Date.now()
    try {
      // We force a new request each time
      await axios.get(targetUrl, {
        httpAgent: agent,
        httpsAgent: agent,
        timeout: maxTimeout,
        validateStatus: status => status === 204 || status === 200 // Strict status check
      })

      const duration = Date.now() - start
      timings.push(duration)

      // Small cooldown between pings to simulate real browsing gaps
      if (i < sampleCount - 1) await new Promise(r => setTimeout(r, 200))

    } catch (e) {
      // ❌ PACKET LOSS DETECTED
      // If even one request fails, the line is not stable enough for high quality.
      return null
    }
  }

  // Calculate Average
  const total = timings.reduce((acc, curr) => acc + curr, 0)
  return Math.round(total / timings.length)
}

/**
 * Helper: Measures Download Speed
 */
async function measureSpeed(agent) {
  try {
    const start = Date.now()
    await axios.get(SPEED_TEST_URL, {
      httpAgent: agent,
      httpsAgent: agent,
      timeout: 15000,
      responseType: 'arraybuffer',
      maxContentLength: SPEED_TEST_FILE_SIZE_MB * 1024 * 1024 * 2
    })
    const durationSec = (Date.now() - start) / 1000

    if (durationSec <= 0) return null
    return ((SPEED_TEST_FILE_SIZE_MB * 8) / durationSec).toFixed(2)
  } catch (e) {
    return null
  }
}

/**
 * Helper: Robust Cleanup
 * Uses SIGKILL to strictly free the port.
 */
async function cleanup(processInstance, filePath) {
  if (processInstance) {
    try {
      processInstance.kill('SIGKILL')
    } catch (e) {}
  }

  try {
    await fs.unlink(filePath)
  } catch (e) {}
}

async function processAndTestConfigs(configsToTest, sourceName) {
  console.log(
    `[Tester] Found ${configsToTest.length} configs from ${sourceName}. Starting tests...`
  )
  const workingConfigs = []

  for (let i = 0; i < configsToTest.length; i += CONCURRENT_TESTS) {
    const batch = configsToTest.slice(i, i + CONCURRENT_TESTS)
    console.log(
      `--- Testing batch ${Math.floor(i / CONCURRENT_TESTS) + 1} of ${Math.ceil(
        configsToTest.length / CONCURRENT_TESTS
      )} ---`
    )
    const testPromises = batch.map((config, index) => testConfig(config, 20800 + index))
    const results = await Promise.all(testPromises)
    workingConfigs.push(...results.filter(Boolean))
  }

  if (workingConfigs.length > 0) {
    workingConfigs.sort(
      (a, b) =>
        b.tags.length - a.tags.length ||
        (b.speedMbps || 0) - (a.speedMbps || 0) ||
        a.latency - b.latency
    )

    const timestamp = new Date().toISOString().replace(/:/g, '-').replace(/\..+/, '')
    const filename = `./results/${sourceName}_${timestamp}.json`

    await fs.writeFile(filename, JSON.stringify(workingConfigs, null, 2))
    console.log(
      `\n[Tester] ✅ Success! Saved ${workingConfigs.length} working configs to ${filename}\n`
    )
  } else {
    console.log(`\n[Tester] ❌ No working configs found for source: ${sourceName}\n`)
  }
}

async function runSingleFileTest(filePath) {
  try {
    const fileContent = await fs.readFile(filePath, 'utf-8')
    const configs = parseConfigsFromText(fileContent)

    if (configs.length === 0) {
      console.log(`[Tester] No valid configs found in ${filePath}.`)
      return
    }

    const sourceName = path.basename(filePath, path.extname(filePath))
    await processAndTestConfigs(configs, sourceName)
  } catch (error) {
    if (error.code === 'ENOENT') {
      console.error(`[Tester] Error: File not found at path: ${filePath}`)
    } else {
      console.error(`[Tester] A critical error occurred during the single file test:`, error)
    }
    process.exit(1)
  }
}

async function runTestCycle() {
  console.log(`\n[Tester] Starting new test cycle at ${new Date().toISOString()}`)

  try {
    let sources = await all('SELECT * FROM config_files')
    if (sources.length === 0) {
      console.log('[Tester] No sources in database. Skipping cycle.')
      return
    }

    sources = sources.sort(() => 0.5 - Math.random())
    let fetchOptions = { timeout: 5000 }
    if (PROXY_URL) {
      const agent = new SocksProxyAgent(PROXY_URL)
      fetchOptions.httpAgent = agent
      fetchOptions.httpsAgent = agent
      console.log(`[Tester] Using Proxy for fetching sources: ${PROXY_URL}`)
    }

    for (const source of sources) {
      console.log(`[Tester] Fetching source: ${source.url}`)
      try {
        const response = await axios.get(source.url, fetchOptions)
        const configs = parseConfigsFromText(response.data)

        if (configs.length > 0) {
          const sourceName = new URL(source.url).pathname.split('/').pop().replace('.txt', '')
          await processAndTestConfigs(configs, sourceName)
        } else {
          console.log(`[Tester] No valid configs found in ${source.url}`)
        }
      } catch (error) {
        console.error(`[Tester] Failed to process source ${source.url}: ${error.message}`)
      }
    }
  } catch (error) {
    console.error('[Tester] A critical error occurred during the test cycle:', error)
  }
}

initialize()
