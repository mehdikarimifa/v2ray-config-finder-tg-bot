import axios from 'axios'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { env } from '@/config/env.js'

export class NetworkTester {
  /**
   * Runs 3 sequential pings. Returns Average Latency or NULL if any fail.
   */
  static async measureStability(agent: SocksProxyAgent): Promise<number | null> {
    const targetUrl = 'http://www.gstatic.com/generate_204'
    const sampleCount = 3
    const timings: number[] = []

    for (let i = 0; i < sampleCount; i++) {
      const start = Date.now()
      try {
        await axios.get(targetUrl, {
          httpAgent: agent,
          httpsAgent: agent,
          timeout: env.MAX_LATENCY_MS,
          validateStatus: status => status === 204 || status === 200
        })

        timings.push(Date.now() - start)
        if (i < sampleCount - 1) await new Promise(r => setTimeout(r, 200))
      } catch (e) {
        return null // Packet Loss
      }
    }

    const total = timings.reduce((acc, curr) => acc + curr, 0)
    return Math.round(total / timings.length)
  }

  /**
   * HYBRID Speed Test
   * - Starts timer AFTER connection is established.
   * - hard caps data at 2MB.
   * - hard caps time at 5 seconds.
   */
  static async measureSpeed(agent: SocksProxyAgent): Promise<string | null> {
    const MAX_BYTES = 2 * 1024 * 1024 // 2 MB Limit
    const MAX_TIME_MS = 5000 // 5 Seconds Limit

    try {
      const response = await axios.get(env.SPEED_TEST_URL, {
        httpAgent: agent,
        httpsAgent: agent,
        responseType: 'stream',
        timeout: 10000,
        validateStatus: () => true
      })

      // We initialize start to 0 and set it ONLY when data starts flowing
      let start = 0
      let downloadedBytes = 0

      return new Promise<string | null>(resolve => {
        const cleanup = () => {
          if (response.data && !response.data.destroyed) {
            response.data.destroy()
          }
        }

        const calculateSpeed = (bytes: number, ms: number) => {
          if (bytes === 0 || ms <= 0) return null

          // Debugging: Uncomment to see raw values in your terminal
          // console.log(`[SpeedDebug] Bytes: ${bytes}, Time: ${ms}ms`)

          const durationSec = ms / 1000
          const bits = bytes * 8
          const mbps = bits / durationSec / 1_000_000
          return mbps.toFixed(2)
        }

        const finish = () => {
          // If we never got data, use current time to prevent negative numbers
          const endTime = Date.now()
          const duration = start === 0 ? 0 : endTime - start
          cleanup()
          resolve(calculateSpeed(downloadedBytes, duration))
        }

        // Safety timeout (5s AFTER first byte, or 10s total if no data)
        const timeoutId = setTimeout(finish, 10000)

        response.data.on('data', (chunk: Buffer) => {
          // 🚀 START TIMER ON FIRST BYTE
          if (start === 0) start = Date.now()

          downloadedBytes += chunk.length
          const elapsed = Date.now() - start

          // Check Limits
          if (downloadedBytes >= MAX_BYTES || elapsed >= MAX_TIME_MS) {
            clearTimeout(timeoutId)
            finish()
          }
        })

        response.data.on('end', () => {
          clearTimeout(timeoutId)
          finish()
        })

        response.data.on('error', () => {
          clearTimeout(timeoutId)
          cleanup()
          resolve(null)
        })
      })
    } catch (e) {
      return null
    }
  }
}
