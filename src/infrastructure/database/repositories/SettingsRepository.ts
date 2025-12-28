import { Database } from '../Database.js'

export class SettingsRepository {
  private db = Database.getInstance()

  /**
   * Generic getter
   */
  async get(key: string): Promise<string | null> {
    const row = await this.db.get<{ value: string }>('SELECT value FROM settings WHERE key = ?', [
      key
    ])
    return row ? row.value : null
  }

  /**
   * Generic setter (Insert or Update)
   */
  async set(key: string, value: string): Promise<void> {
    await this.db.run('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', [key, value])
  }

  /**
   * Typed helper for the Posting Interval
   * Defaults to 1800 seconds (30 mins) if not set.
   */
  async getPostingInterval(): Promise<number> {
    const val = await this.get('posting_interval_seconds')
    return val ? parseInt(val, 10) : 1800
  }

  async setPostingInterval(seconds: number): Promise<void> {
    await this.set('posting_interval_seconds', seconds.toString())
  }
}
