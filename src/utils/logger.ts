type LogLevel = 'INFO' | 'WARN' | 'ERROR' | 'SUCCESS'

export const logger = {
  info: (msg: string, context: string = 'System') => {
    console.log(`[${new Date().toISOString()}] [INFO] [${context}] ${msg}`)
  },
  warn: (msg: string, context: string = 'System') => {
    console.warn(`[${new Date().toISOString()}] [WARN] [${context}] ${msg}`)
  },
  error: (msg: string, error?: unknown, context: string = 'System') => {
    console.error(`[${new Date().toISOString()}] [ERROR] [${context}] ${msg}`, error || '')
  },
  success: (msg: string, context: string = 'System') => {
    console.log(`[${new Date().toISOString()}] [✅ SUCCESS] [${context}] ${msg}`)
  }
}
