import TelegramBot from 'node-telegram-bot-api'
import fs from 'fs/promises'
import path from 'path'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { env } from '@/config/env.js'
import { logger } from '@/utils/logger.js'
import { Database } from '@/infrastructure/database/Database.js'
import { SourceRepository } from '@/infrastructure/database/repositories/SourceRepository.js'
import { ITestResult } from '@/types/index.js'

export class BotEngine {
  private bot: TelegramBot
  private db = Database.getInstance()
  private sourceRepo = new SourceRepository()
  private postingInterval: NodeJS.Timeout | null = null

  constructor() {
    const options: TelegramBot.ConstructorOptions = { polling: true }
    if (env.PROXY_URL) {
      options.request = { agent: new SocksProxyAgent(env.PROXY_URL) } as any
    }
    this.bot = new TelegramBot(env.BOT_TOKEN, options)
  }

  public async start() {
    logger.info('Bot started. Listening for commands...')
    this.registerCommands()
    await this.startScheduler()
  }

  private registerCommands() {
    // Auth Middleware
    this.bot.on('message', msg => {
      if (msg.from?.id !== env.ADMIN_USER_ID) {
        // Silent ignore or reply access denied
      }
    })

    this.bot.onText(/\/start/, msg => {
      if (msg.from?.id !== env.ADMIN_USER_ID) return
      this.bot.sendMessage(msg.chat.id, '👋 Admin Online.')
    })

    this.bot.onText(/\/addfile (.+)/, async (msg, match) => {
      if (msg.from?.id !== env.ADMIN_USER_ID || !match) return
      try {
        await this.sourceRepo.addSource(match[1])
        this.bot.sendMessage(msg.chat.id, '✅ Source added.')
      } catch (e) {
        this.bot.sendMessage(msg.chat.id, '❌ Error adding source.')
      }
    })

    this.bot.onText(/\/removefile (.+)/, async (msg, match) => {
      if (msg.from?.id !== env.ADMIN_USER_ID || !match) return

      const id = parseInt(match[1], 10)
      if (isNaN(id)) {
        this.bot.sendMessage(msg.chat.id, '❌ Invalid ID. Please provide a number.')
        return
      }

      try {
        const success = await this.sourceRepo.removeSource(id)
        if (success) {
          this.bot.sendMessage(msg.chat.id, `✅ Success! Source ID ${id} removed.`)
        } else {
          this.bot.sendMessage(msg.chat.id, `⚠️ Source ID ${id} not found.`)
        }
      } catch (e) {
        this.bot.sendMessage(msg.chat.id, '❌ Error removing source.')
        logger.error('Error removing source', e)
      }
    })

    this.bot.onText(/\/listfiles/, async msg => {
      if (msg.from?.id !== env.ADMIN_USER_ID) return
      const files = await this.sourceRepo.getAllActiveSources()
      const text = files.map(f => `ID: ${f.id} | ${f.url}`).join('\n') || 'No files.'
      this.bot.sendMessage(msg.chat.id, text)
    })
  }

  private async startScheduler() {
    const row = await this.db.get<{ value: string }>(
      "SELECT value FROM settings WHERE key = 'posting_interval_seconds'"
    )
    const seconds = row ? parseInt(row.value, 10) : 1800 // Default 30 mins

    logger.info(`Posting schedule: Every ${seconds} seconds.`)

    if (this.postingInterval) clearInterval(this.postingInterval)
    this.postingInterval = setInterval(() => this.postBatch(), seconds * 1000)

    // Run once immediately
    this.postBatch()
  }

  private async postBatch() {
    // Constants for this method
    const RESULTS_DIR = path.join(process.cwd(), 'results')
    const POST_BATCH_SIZE = 5
    const MAX_CONFIG_AGE_HOURS = 24

    try {
      // --- 1. Aggregate all available configs ---
      // We read all JSON files in the results folder
      const files = await fs.readdir(RESULTS_DIR)
      let allConfigs: ITestResult[] = []

      for (const file of files) {
        if (!file.endsWith('.json')) continue

        const filePath = path.join(RESULTS_DIR, file)
        try {
          const data = await fs.readFile(filePath, 'utf-8')
          const parsedConfigs: ITestResult[] = JSON.parse(data)
          allConfigs.push(...parsedConfigs)

          // Delete the file immediately so we don't process it twice
          await fs.unlink(filePath)
        } catch (e) {
          logger.error(`Error processing file ${file}`, e)
        }
      }

      if (allConfigs.length === 0) {
        logger.info('No new configs to post.')
        return
      }

      // --- 2. Filter out old/zombie configs ---
      const now = new Date()
      const initialCount = allConfigs.length

      allConfigs = allConfigs.filter(c => {
        if (!c.tested_at) return false
        const testedDate = new Date(c.tested_at)
        const ageInHours = (now.getTime() - testedDate.getTime()) / (1000 * 60 * 60)
        return ageInHours < MAX_CONFIG_AGE_HOURS
      })

      if (initialCount > allConfigs.length) {
        logger.info(`Cleaned up ${initialCount - allConfigs.length} expired configs.`)
      }

      if (allConfigs.length === 0) return

      // --- 3. Sort (Speed > Latency) ---
      allConfigs.sort(
        (a, b) =>
          (b.tags?.length || 0) - (a.tags?.length || 0) || // Prefer tagged configs
          parseFloat(b.speedMbps || '0') - parseFloat(a.speedMbps || '0') || // Higher Speed
          (a.latency || 9999) - (b.latency || 9999) // Lower Latency
      )

      // --- 4. Smart Selection ---
      const batchToPost: ITestResult[] = []

      // Always take the #1 best config
      if (allConfigs.length > 0) batchToPost.push(allConfigs.shift()!)

      // Fill the rest with random valid configs (to avoid posting only one provider repeatedly)
      const remainingSpots = POST_BATCH_SIZE - batchToPost.length
      for (let i = 0; i < remainingSpots && allConfigs.length > 0; i++) {
        const randomIndex = Math.floor(Math.random() * allConfigs.length)
        batchToPost.push(allConfigs.splice(randomIndex, 1)[0])
      }

      if (batchToPost.length === 0) return

      // --- 5. Format & Post ---
      const cleanChannelLink = `https://t.me/${env.TARGET_CHANNEL_ID.replace('@', '')}`

      const formattedConfigs = batchToPost
        .map(c => {
          const flag = this.getFlagEmoji(c.countryCode, c.name)
          const speedInfo = c.speedMbps ? `⚡️ ${c.speedMbps} Mbps` : ''
          const latencyInfo = c.latency ? `📶 ${c.latency}ms` : ''
          const hashtags = c.tags ? c.tags.join(' ') : ''

          // Create a custom remark/name for the config
          const remarkName = `${flag} - ${speedInfo} ${env.TARGET_CHANNEL_ID}`

          // Append remark to the config (Basic hash manipulation)
          const configPart = c.config.split('#')[0]
          const configWithRemark = `${configPart}#${encodeURIComponent(remarkName)}`

          return `<code>${configWithRemark}</code>\n${flag} ${[latencyInfo, speedInfo, hashtags]
            .filter(Boolean)
            .join(' | ')}`
        })
        .join('\n\n')

      const message = `${formattedConfigs}\n\n- ${cleanChannelLink}`

      await this.bot.sendMessage(env.TARGET_CHANNEL_ID, message, {
        parse_mode: 'HTML',
        disable_notification: true
      })

      logger.success(`Posted a smart batch of ${batchToPost.length} configs.`)

      // --- 6. Recycle Remaining Configs ---
      // Save leftovers back to a file so they can be picked up in the next cycle
      if (allConfigs.length > 0) {
        const masterPoolPath = path.join(RESULTS_DIR, `_pool_${Date.now()}.json`)
        await fs.writeFile(masterPoolPath, JSON.stringify(allConfigs, null, 2))
        logger.info(`Saved ${allConfigs.length} remaining configs to the pool.`)
      }
    } catch (e) {
      logger.error('Error during posting cycle', e)
    }
  }

  // Helper: Converts Country Code to Emoji
  private getFlagEmoji(countryCode: string, name: string): string {
    // 1. Try ISO code
    if (countryCode && countryCode.length === 2 && countryCode !== 'XX') {
      try {
        return String.fromCodePoint(
          ...countryCode
            .toUpperCase()
            .split('')
            .map(c => 127397 + c.charCodeAt(0))
        )
      } catch (e) {}
    }
    // 2. Fallback: Check if name already has a flag
    const match = name.match(/\p{Regional_Indicator}{2}/u)
    return match ? match[0] : '🏁'
  }
}
