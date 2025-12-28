import { spawn, ChildProcess } from 'child_process'
import fs from 'fs/promises'
import { logger } from '@/utils/logger.js'
import { env } from '@/config/env.js'

export class XrayInstance {
  private process: ChildProcess | null = null

  constructor(private configPath: string) {}

  async start(): Promise<void> {
    this.process = spawn(env.XRAY_BIN, ['-c', this.configPath])

    // Wait for Xray to initialize
    await new Promise(resolve => setTimeout(resolve, 500))
  }

  async stop(): Promise<void> {
    if (this.process) {
      try {
        this.process.kill('SIGKILL')
      } catch (e) {
        logger.warn('Failed to kill Xray process', 'Xray')
      }
    }
    try {
      await fs.unlink(this.configPath)
    } catch (e) {
      // Ignore unlink errors
    }
  }
}
