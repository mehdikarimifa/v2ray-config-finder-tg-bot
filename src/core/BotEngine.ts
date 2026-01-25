import TelegramBot from 'node-telegram-bot-api'
import fs from 'fs/promises'
import path from 'path'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { env } from '@/config/env.js'
import { logger } from '@/utils/logger.js'
import { SourceRepository } from '@/infrastructure/database/repositories/SourceRepository.js'
import { SettingsRepository } from '@/infrastructure/database/repositories/SettingsRepository.js'
import { ConfigRepository } from '@/infrastructure/database/repositories/ConfigRepository.js'
import { ITestResult } from '@/types/index.js'

export class BotEngine {
  private bot: TelegramBot
  private sourceRepo = new SourceRepository()
  private settingsRepo = new SettingsRepository()
  private configRepo = new ConfigRepository() // [NEW]
  private postingInterval: NodeJS.Timeout | null = null

  constructor() {
    const options: TelegramBot.ConstructorOptions = {
      polling: {
        interval: 300,
        autoStart: true,
        params: { timeout: 10 }
      }
    }

    if (env.PROXY_URL) {
      const agent = new SocksProxyAgent(env.PROXY_URL, { timeout: 60000, keepAlive: true })
      options.request = { agent, timeout: 60000 } as any
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

    this.bot.onText(/\/setschedule (.+)/, async (msg, match) => {
      if (msg.from?.id !== env.ADMIN_USER_ID || !match) return

      const seconds = parseInt(match[1], 10)
      if (isNaN(seconds) || seconds < 60) {
        this.bot.sendMessage(msg.chat.id, '⚠️ Minimum interval is 60 seconds.')
        return
      }

      try {
        await this.settingsRepo.setPostingInterval(seconds)
        this.bot.sendMessage(msg.chat.id, `✅ Schedule updated: Every ${seconds} seconds.`)

        // Restart the scheduler immediately to apply changes
        await this.startScheduler()
      } catch (e) {
        this.bot.sendMessage(msg.chat.id, '❌ Error updating schedule.')
      }
    })

    this.bot.onText(/\/getschedule/, async msg => {
      if (msg.from?.id !== env.ADMIN_USER_ID) return

      const seconds = await this.settingsRepo.getPostingInterval()
      this.bot.sendMessage(msg.chat.id, `⏱ Current posting interval: ${seconds} seconds.`)
    })
  }

  private async startScheduler() {
    const seconds = await this.settingsRepo.getPostingInterval()
    logger.info(`Scheduler active: Posting every ${seconds} seconds.`)

    if (this.postingInterval) clearInterval(this.postingInterval)
    this.postingInterval = setInterval(() => this.postBatch(), seconds * 1000)
  }

  private async postBatch() {
    const RESULTS_DIR = path.join(process.cwd(), 'results')
    const BATCH_SIZE = 5 // Configs per post
    const MAX_AGE_HOURS = 24

    try {
      const files = await fs.readdir(RESULTS_DIR)
      for (const file of files) {
        if (!file.endsWith('.json')) continue
        try {
          const filePath = path.join(RESULTS_DIR, file)
          const data = await fs.readFile(filePath, 'utf-8')
          const parsed: ITestResult[] = JSON.parse(data)

          await this.configRepo.addToPool(parsed)

          await fs.unlink(filePath)
        } catch (e) {
          logger.error(`Error ingesting file ${file}`, e)
        }
      }

      await this.configRepo.cleanupOld(MAX_AGE_HOURS)

      const batchToPost = await this.configRepo.getBestFromPool(BATCH_SIZE)
      if (batchToPost.length === 0) {
        logger.info('Pool empty. Nothing to post.')
        return
      }

      const cleanChannelLink = `https://t.me/${env.TARGET_CHANNEL_ID.replace('@', '')}`
      const formattedConfigs = batchToPost
        .map(c => {
          const flag = this.getFlagEmoji(c.countryCode, c.name)
          const speedInfo = c.speedMbps ? `⚡️ ${c.speedMbps} Mbps` : ''
          const latencyInfo = c.latency ? `📶 ${c.latency}ms` : ''
          const hashtags = c.tags ? c.tags.join(' ') : ''
          const remarkName = `${flag} - ${speedInfo} ${env.TARGET_CHANNEL_ID}`

          const configPart = c.config.split('#')[0]
          const configWithRemark = `${configPart}#${encodeURIComponent(remarkName)}`

          return `<code>${configWithRemark}</code>\n${flag} ${[latencyInfo, speedInfo, hashtags].filter(Boolean).join(' | ')}`
        })
        .join('\n\n')

      const message = `${formattedConfigs}\n\n- ${cleanChannelLink}`

      await this.bot.sendMessage(env.TARGET_CHANNEL_ID, message, {
        parse_mode: 'HTML',
        disable_notification: true
      })

      logger.success(`Posted batch of ${batchToPost.length} configs.`)

      const postedLinks = batchToPost.map(c => c.config)
      await this.configRepo.removeFromPool(postedLinks)
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
