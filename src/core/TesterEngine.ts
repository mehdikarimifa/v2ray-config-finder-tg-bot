import axios from 'axios'
import fs from 'fs/promises'
import path from 'path'
import crypto from 'crypto'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { env } from '@/config/env.js'
import { logger } from '@/utils/logger.js'
import { SourceRepository } from '@/infrastructure/database/repositories/SourceRepository.js'
import { ParserService } from '@/services/ParserService.js'
import { ConfigBuilder } from '@/infrastructure/xray/ConfigBuilder.js'
import { XrayInstance } from '@/infrastructure/xray/XrayInstance.js'
import { NetworkTester } from '@/services/NetworkTester.js'
import { IpService } from '@/services/IpService.js'
import { ITestResult } from '@/types/index.js'

export class TesterEngine {
  private sourceRepo = new SourceRepository()

  public async start(singleFilePath?: string) {
    if (singleFilePath) {
      logger.info(`Starting in single-file mode for: ${singleFilePath}`)
      await this.runSingleFile(singleFilePath)
      process.exit(0)
    }

    logger.info('Starting in scheduled mode.')
    // Initial run
    await this.runCycle()

    // Schedule loop
    setInterval(() => this.runCycle(), env.TEST_INTERVAL_MINUTES * 60 * 1000)
  }

  private async runCycle() {
    logger.info('Starting new test cycle...')
    try {
      const sources = await this.sourceRepo.getAllActiveSources()
      if (sources.length === 0) {
        logger.warn('No sources in database.')
        return
      }

      // Shuffle sources
      const shuffled = sources.sort(() => 0.5 - Math.random())

      const fetchOptions: any = { timeout: 5000 }
      if (env.PROXY_URL) {
        const agent = new SocksProxyAgent(env.PROXY_URL)
        fetchOptions.httpAgent = agent
        fetchOptions.httpsAgent = agent
      }

      for (const source of shuffled) {
        logger.info(`Fetching source: ${source.url}`)
        try {
          const response = await axios.get(source.url, fetchOptions)
          const configs = ParserService.parseConfigsFromText(response.data)

          if (configs.length > 0) {
            const sourceName =
              new URL(source.url).pathname.split('/').pop()?.replace('.txt', '') || 'unknown'
            await this.processBatch(configs, sourceName)
          }
        } catch (e: any) {
          logger.error(`Failed to process source ${source.url}`, e)
        }
      }
    } catch (e) {
      logger.error('Critical error in test cycle', e)
    }
  }

  private async runSingleFile(filePath: string) {
    try {
      const content = await fs.readFile(filePath, 'utf-8')
      const configs = ParserService.parseConfigsFromText(content)
      const sourceName = path.basename(filePath, path.extname(filePath))
      await this.processBatch(configs, sourceName)
    } catch (e) {
      logger.error('Error reading single file', e)
    }
  }

  private async processBatch(configs: string[], sourceName: string) {
    logger.info(`Testing ${configs.length} configs from ${sourceName}...`)
    const results: ITestResult[] = []
    const BATCH_SIZE = env.CONCURRENT_TESTS

    for (let i = 0; i < configs.length; i += BATCH_SIZE) {
      const batch = configs.slice(i, i + BATCH_SIZE)
      const promises = batch.map((cfg, idx) => this.testConfig(cfg, 20800 + idx))
      const batchResults = await Promise.all(promises)
      results.push(...(batchResults.filter(Boolean) as ITestResult[]))
    }

    if (results.length > 0) {
      await this.saveResults(results, sourceName)
    } else {
      logger.info(`No working configs found for ${sourceName}`)
    }
  }

  private async testConfig(originalLink: string, port: number): Promise<ITestResult | null> {
    const parsed = ParserService.parseLink(originalLink)
    if (!parsed) return null

    const xrayConfig = ConfigBuilder.build(parsed, port)
    if (!xrayConfig) return null

    // Unique temp file
    const tempPath = path.join(
      process.cwd(),
      'tmp',
      `test_${port}_${crypto.randomBytes(4).toString('hex')}.json`
    )

    // Ensure tmp dir exists
    await fs.mkdir(path.dirname(tempPath), { recursive: true })
    await fs.writeFile(tempPath, JSON.stringify(xrayConfig))

    const xray = new XrayInstance(tempPath)

    try {
      await xray.start()
      const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${port}`)

      // 1. Stability Check (The strict logic we added)
      const latency = await NetworkTester.measureStability(agent)
      if (latency === null) return null

      // 2. Speed Test
      let speedMbps = null
      if (env.ENABLE_SPEED_TEST) {
        speedMbps = await NetworkTester.measureSpeed(agent)
      }

      // 2. Active Geo-Location (The New Feature)
      // We ask the proxy: "Where are we?"
      const geo = await IpService.getGeoInfo(agent)

      logger.success(`(Lat: ${latency}ms) ${parsed.details.ps}`)

      return {
        config: originalLink,
        name: parsed.details.ps || 'Unknown',
        latency,
        speedMbps,
        countryCode: geo.countryCode,
        countryName: geo.countryName,
        tags: [],
        tested_at: new Date().toISOString()
      }
    } catch (e) {
      return null
    } finally {
      await xray.stop()
    }
  }

  private async saveResults(results: ITestResult[], sourceName: string) {
    const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0]
    const filename = path.join(process.cwd(), 'results', `${sourceName}_${timestamp}.json`)

    await fs.mkdir(path.dirname(filename), { recursive: true })

    // Sort: Tags -> Speed -> Latency
    results.sort(
      (a, b) =>
        (b.speedMbps ? parseFloat(b.speedMbps) : 0) - (a.speedMbps ? parseFloat(a.speedMbps) : 0) ||
        (a.latency || 9999) - (b.latency || 9999)
    )

    await fs.writeFile(filename, JSON.stringify(results, null, 2))
    logger.success(`Saved ${results.length} configs to ${filename}`)
  }
}
