import sqlite3 from 'sqlite3'
import { env } from '@/config/env.js'
import { logger } from '@/utils/logger.js'

export class Database {
  private static instance: Database
  private db: sqlite3.Database

  private constructor() {
    this.db = new sqlite3.Database(env.DB_PATH, err => {
      if (err) {
        logger.error('Failed to connect to SQLite', err)
        process.exit(1)
      }
      logger.info('Connected to SQLite database.')
    })
  }

  public static getInstance(): Database {
    if (!Database.instance) {
      Database.instance = new Database()
    }
    return Database.instance
  }

  public async init(): Promise<void> {
    const queries = [
      `CREATE TABLE IF NOT EXISTS config_files (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL UNIQUE, added_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS posted_configs (id INTEGER PRIMARY KEY AUTOINCREMENT, config_hash TEXT NOT NULL UNIQUE, posted_at DATETIME DEFAULT CURRENT_TIMESTAMP)`,
      `CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)`
    ]

    for (const query of queries) {
      await this.run(query)
    }
    logger.info('Database tables initialized.')
  }

  public get<T>(query: string, params: any[] = []): Promise<T | undefined> {
    return new Promise((resolve, reject) => {
      this.db.get(query, params, (err, row) => {
        if (err) reject(err)
        else resolve(row as T)
      })
    })
  }

  public all<T>(query: string, params: any[] = []): Promise<T[]> {
    return new Promise((resolve, reject) => {
      this.db.all(query, params, (err, rows) => {
        if (err) reject(err)
        else resolve(rows as T[])
      })
    })
  }

  public run(query: string, params: any[] = []): Promise<{ changes: number; lastID: number }> {
    return new Promise((resolve, reject) => {
      this.db.run(query, params, function (err) {
        if (err) reject(err)
        else resolve({ changes: this.changes, lastID: this.lastID })
      })
    })
  }
}
