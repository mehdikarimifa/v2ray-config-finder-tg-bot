import { Database } from '../Database.js'
import { ITestResult } from '@/types/index.js'
import { logger } from '@/utils/logger.js'

export class ConfigRepository {
  private db = Database.getInstance()

  /**
   * Import a batch of test results into the DB.
   * Ignores duplicates (based on the original link).
   */
  async addToPool(results: ITestResult[]): Promise<void> {
    const stmt =
      'INSERT OR IGNORE INTO config_pool (original_link, latency, speed_mbps, tested_at, full_json) VALUES (?, ?, ?, ?, ?)'

    let count = 0
    for (const res of results) {
      // Convert string speed ("5.2 Mbps") to float (5.2) for sorting
      const speedVal = res.speedMbps ? parseFloat(res.speedMbps) : 0
      const latencyVal = res.latency || 9999

      try {
        await this.db.run(stmt, [
          res.config,
          latencyVal,
          speedVal,
          res.tested_at,
          JSON.stringify(res)
        ])
        count++
      } catch (e) {
        logger.error('Error inserting config to pool', e)
      }
    }
    if (count > 0) logger.info(`Added ${count} new configs to the pool.`)
  }

  /**
   * Get the 'limit' best configs (Highest Speed, then Lowest Latency).
   */
  async getBestFromPool(limit: number): Promise<ITestResult[]> {
    // We order by Speed DESC, then Latency ASC
    const rows = await this.db.all<{ full_json: string; id: number }>(
      `SELECT full_json, id FROM config_pool 
       ORDER BY speed_mbps DESC, latency ASC 
       LIMIT ?`,
      [limit]
    )

    return rows.map(row => JSON.parse(row.full_json))
  }

  /**
   * Remove configs from the pool (e.g. after posting).
   */
  async removeFromPool(links: string[]): Promise<void> {
    if (links.length === 0) return
    const placeholders = links.map(() => '?').join(',')
    await this.db.run(`DELETE FROM config_pool WHERE original_link IN (${placeholders})`, links)
  }

  /**
   * Delete configs older than X hours.
   */
  async cleanupOld(maxAgeHours: number): Promise<void> {
    // SQLite datetime comparison: tested_at < datetime('now', '-24 hours')
    await this.db.run(
      `DELETE FROM config_pool WHERE tested_at < datetime('now', '-' || ? || ' hours')`,
      [maxAgeHours]
    )
  }
}
