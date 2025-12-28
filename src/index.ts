import { Database } from './infrastructure/database/Database.js'
import { TesterEngine } from './core/TesterEngine.js'
import { BotEngine } from './core/BotEngine.js'
import { logger } from './utils/logger.js'

const main = async () => {
  // Initialize Database first
  await Database.getInstance().init()

  const mode = process.argv[2] // e.g., 'tester' or 'bot'

  if (mode === 'tester') {
    const tester = new TesterEngine()
    // Check for --file arg
    const fileArgIndex = process.argv.indexOf('--file')
    const singleFile = fileArgIndex > -1 ? process.argv[fileArgIndex + 1] : undefined

    await tester.start(singleFile)
  } else if (mode === 'bot') {
    const bot = new BotEngine()
    await bot.start()
  } else {
    logger.error('Please specify mode: "node dist/index.js tester" or "node dist/index.js bot"')
    process.exit(1)
  }
}

main().catch(err => logger.error('Fatal App Error', err))
