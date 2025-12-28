import axios from 'axios'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { IGeoInfo } from '../types/index.js'

export class IpService {
  private static API_URL = 'http://ip-api.com/json/?fields=country,countryCode,query'

  /**
   * ACTIVE Location Check
   * Connects THROUGH the proxy to find the real exit IP and location.
   */
  static async getGeoInfo(agent: SocksProxyAgent): Promise<IGeoInfo> {
    try {
      const response = await axios.get(this.API_URL, {
        httpAgent: agent,
        httpsAgent: agent, // Support both http/https proxies
        timeout: 5000 // Give it 5s to resolve
      })

      if (response.data && response.data.countryCode) {
        return {
          countryCode: response.data.countryCode,
          countryName: response.data.country
        }
      }
    } catch (e) {
      // If the strict lookup fails, we just return Unknown rather than guessing.
      // Often if ip-api fails, the proxy might have internet issues anyway.
    }

    return { countryCode: 'XX', countryName: 'Unknown' }
  }
}
