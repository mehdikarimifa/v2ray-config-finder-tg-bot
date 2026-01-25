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
import { ITestResult, IParsedConfig } from '@/types/index.js'

export class TesterEngine {
  private sourceRepo = new SourceRepository()

  public async start(singleFilePath?: string) {
    if (singleFilePath) {
      logger.info(`Starting in single-file mode for: ${singleFilePath}`)
      await this.runSingleFile(singleFilePath)
      process.exit(0)
    }

    logger.info('Starting in scheduled mode.')
    await this.runCycle() // Initial run

    const intervalMs = env.TEST_INTERVAL_MINUTES * 60 * 1000
    setInterval(() => this.runCycle(), intervalMs)
  }

  private async runCycle() {
    logger.info('Starting new test cycle...')
    try {
      const sources = await this.sourceRepo.getAllActiveSources()
      if (sources.length === 0) {
        logger.warn('No sources in database.')
        return
      }

      const shuffled = sources.sort(() => 0.5 - Math.random())

      const fetchOptions: any = { timeout: 50000 }
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
            await this.processConfigs(configs, sourceName)
          }
        } catch (e: any) {
          logger.error(`Failed to process source ${source.url}`, e.message)
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
      await this.processConfigs(configs, sourceName)
    } catch (e) {
      logger.error('Error reading single file', e)
    }
  }

  /**
   * Main Batch Processing Logic
   */
  private async processConfigs(rawConfigs: string[], sourceName: string) {
    const results: ITestResult[] = []
    const BATCH_SIZE = env.CONCURRENT_TESTS
    const START_PORT = 20000 // Base port to prevent conflicts

    // Parse all first
    const parsedConfigs: IParsedConfig[] = rawConfigs
      .map(link => ParserService.parseLink(link))
      .filter((c): c is IParsedConfig => c !== null)

    logger.info(`Testing ${parsedConfigs.length} valid configs from ${sourceName}...`)

    // Loop in chunks
    for (let i = 0; i < parsedConfigs.length; i += BATCH_SIZE) {
      const chunk = parsedConfigs.slice(i, i + BATCH_SIZE)

      // Prepare batch items
      const batchItems = chunk.map((config, idx) => ({
        config,
        port: START_PORT + idx,
        id: idx
      }))

      // Build Multi-Inbound Config
      const xrayConfig = ConfigBuilder.buildBatch(batchItems)
      if (!xrayConfig) continue

      // Write Temp File
      const tempId = crypto.randomBytes(4).toString('hex')
      const tempPath = path.join(process.cwd(), 'tmp', `batch_${tempId}.json`)
      await fs.mkdir(path.dirname(tempPath), { recursive: true })
      await fs.writeFile(tempPath, JSON.stringify(xrayConfig))

      const xray = new XrayInstance(tempPath)

      try {
        await xray.start()

        // Run tests in parallel
        const promises = batchItems.map(item => this.testSingleInBatch(item))
        const batchResults = await Promise.all(promises)

        results.push(...(batchResults.filter(Boolean) as ITestResult[]))
      } catch (e) {
        logger.error('Batch execution failed', e)
      } finally {
        await xray.stop()
      }
    }

    if (results.length > 0) {
      await this.saveResults(results, sourceName)
    }
  }

  private async testSingleInBatch(item: {
    config: IParsedConfig
    port: number
  }): Promise<ITestResult | null> {
    const { config, port } = item
    const agent = new SocksProxyAgent(`socks5h://127.0.0.1:${port}`)

    try {
      // 1. Stability
      const latency = await NetworkTester.measureStability(agent)
      if (latency === null) return null

      // 2. Speed (Optional)
      let speedMbps = null
      if (env.ENABLE_SPEED_TEST) {
        speedMbps = await NetworkTester.measureSpeed(agent)
      }

      // 3. Geo
      const geo = await IpService.getGeoInfo(agent)

      logger.success(`(Lat: ${latency}ms) ${config.details.ps}`)

      return {
        config: config.originalLink,
        name: config.details.ps || 'Unknown',
        latency,
        speedMbps,
        countryCode: geo.countryCode,
        countryName: geo.countryName,
        tags: [],
        tested_at: new Date().toISOString()
      }
    } catch (e) {
      return null
    }
  }

  private async saveResults(results: ITestResult[], sourceName: string) {
    const timestamp = new Date().toISOString().replace(/:/g, '-').split('.')[0]
    const filename = path.join(process.cwd(), 'results', `${sourceName}_${timestamp}.json`)
    await fs.mkdir(path.dirname(filename), { recursive: true })

    results.sort(
      (a, b) =>
        (b.speedMbps ? parseFloat(b.speedMbps) : 0) - (a.speedMbps ? parseFloat(a.speedMbps) : 0) ||
        (a.latency || 9999) - (b.latency || 9999)
    )

    await fs.writeFile(filename, JSON.stringify(results, null, 2))
    logger.success(`Saved ${results.length} working configs to ${filename}`)
  }
}
