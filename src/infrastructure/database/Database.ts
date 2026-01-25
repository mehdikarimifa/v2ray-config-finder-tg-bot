import DatabaseConstructor, { Database as SQLiteDB } from 'better-sqlite3'
import { env } from '@/config/env.js'
import { logger } from '@/utils/logger.js'

export class Database {
  private static instance: Database
  private db: SQLiteDB

  private constructor() {
    try {
      this.db = new DatabaseConstructor(env.DB_PATH)
      this.db.pragma('journal_mode = WAL')
      logger.info('Connected to SQLite database (better-sqlite3).')
    } catch (e) {
      logger.error('Failed to connect to SQLite', e)
      process.exit(1)
    }
  }

  public static getInstance(): Database {
    if (!Database.instance) Database.instance = new Database()

    return Database.instance
  }

  public async init(): Promise<void> {
    const queries = [
      `CREATE TABLE IF NOT EXISTS config_files (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, added_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS posted_configs (id INTEGER PRIMARY KEY AUTOINCREMENT, config_hash TEXT NOT NULL UNIQUE, posted_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`,
      `CREATE TABLE IF NOT EXISTS config_pool (
         id INTEGER PRIMARY KEY AUTOINCREMENT,
         original_link TEXT UNIQUE,
         latency INTEGER,
         speed_mbps REAL,
         tested_at DATETIME,
         full_json TEXT
      )`
    ]

    try {
      for (const query of queries) {
        this.db.prepare(query).run()
      }
      logger.info('Database tables initialized.')
    } catch (e) {
      logger.error('Failed to initialize tables', e)
      throw e
    }
  }

  public async get<T>(query: string, params: any[] = []): Promise<T | undefined> {
    const stmt = this.db.prepare(query)
    return stmt.get(...params) as T
  }

  public async all<T>(query: string, params: any[] = []): Promise<T[]> {
    const stmt = this.db.prepare(query)
    return stmt.all(...params) as T[]
  }

  public async run(
    query: string,
    params: any[] = []
  ): Promise<{ changes: number; lastID: number }> {
    const stmt = this.db.prepare(query)
    const info = stmt.run(...params)
    return { changes: info.changes, lastID: Number(info.lastInsertRowid) }
  }
}
