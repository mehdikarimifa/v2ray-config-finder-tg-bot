import { Database } from '../Database.js'

export interface ISourceFile {
  id: number
  url: string
}

export class SourceRepository {
  private db = Database.getInstance()

  async getAllActiveSources(): Promise<ISourceFile[]> {
    return this.db.all<ISourceFile>('SELECT * FROM config_files')
  }

  async addSource(url: string): Promise<void> {
    await this.db.run('INSERT INTO config_files (url) VALUES (?)', [url])
  }

  async removeSource(id: number): Promise<boolean> {
    const result = await this.db.run('DELETE FROM config_files WHERE id = ?', [id])
    return result.changes > 0
  }
}
