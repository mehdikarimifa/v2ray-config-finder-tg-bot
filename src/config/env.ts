import 'dotenv/config'

interface EnvConfig {
  BOT_TOKEN: string
  ADMIN_USER_ID: number
  TARGET_CHANNEL_ID: string
  XRAY_BIN: string
  TEST_INTERVAL_MINUTES: number
  CONCURRENT_TESTS: number
  MAX_LATENCY_MS: number
  ENABLE_SPEED_TEST: boolean
  SPEED_TEST_URL: string
  SPEED_TEST_FILE_SIZE_MB: number
  DB_PATH: string
  PROXY_URL?: string
}

// Validation
const required = (key: string): string => {
  const value = process.env[key]
  if (!value) {
    throw new Error(`❌ FATAL: Missing required environment variable: ${key}`)
  }
  return value
}

export const env: EnvConfig = {
  BOT_TOKEN: required('BOT_TOKEN'),
  ADMIN_USER_ID: parseInt(required('ADMIN_USER_ID'), 10),
  TARGET_CHANNEL_ID: required('TARGET_CHANNEL_ID'),

  XRAY_BIN: process.env.XRAY_BIN || './xray',
  TEST_INTERVAL_MINUTES: parseInt(process.env.TEST_INTERVAL_MINUTES || '30', 10),
  CONCURRENT_TESTS: parseInt(process.env.CONCURRENT_TESTS || '10', 10),
  MAX_LATENCY_MS: parseInt(process.env.MAX_LATENCY_MS || '1500', 10),

  ENABLE_SPEED_TEST: process.env.ENABLE_SPEED_TEST === 'true',
  SPEED_TEST_URL: process.env.SPEED_TEST_URL || 'http://cachefly.cachefly.net/5mb.test',
  SPEED_TEST_FILE_SIZE_MB: parseInt(process.env.SPEED_TEST_FILE_SIZE_MB || '5', 10),

  DB_PATH: process.env.DB_PATH || './v2ray_bot.sqlite',
  PROXY_URL: process.env.PROXY_URL || undefined
}
