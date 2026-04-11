import https from 'https'

export interface CategoryResult {
  domain: string
  category: string
  confidence: number
  isBlocked: boolean
  source: 'api' | 'timeout'
}

const BLOCKED_CATEGORIES = ['adult', 'pornography', 'adult-content', 'nsfw']

export class Categorizer {
  async categorize(domain: string): Promise<CategoryResult> {
    const cleanDomain = domain.replace(/^www\./, '')

    const result = await Promise.race([
      this.queryURLhaus(cleanDomain),
      new Promise<CategoryResult>(resolve => 
        setTimeout(() => resolve({
          domain: cleanDomain,
          category: 'uncategorized',
          confidence: 0,
          isBlocked: false,
          source: 'timeout'
        }), 3000)
      )
    ])

    return result
  }

  private queryURLhaus(domain: string): Promise<CategoryResult> {
    return new Promise((resolve) => {
      const options = {
        hostname: 'urlhaus-api.abuse.ch',
        path: `/v1/urls/on_host/?host=${encodeURIComponent(domain)}`,
        method: 'GET',
        timeout: 2500
      }

      const req = https.request(options, (res) => {
        let data = ''

        res.on('data', (chunk) => {
          data += chunk
        })

        res.on('end', () => {
          try {
            const json = JSON.parse(data)

            if (json.urls && json.urls.length > 0) {
              const urls = json.urls as Array<{ threat: string; tags: string[] }>
              const threatData = urls[0]
              const category = threatData.threat?.toLowerCase() || 'unknown'
              const tags = threatData.tags || []

              if (BLOCKED_CATEGORIES.some(c => category.includes(c) || tags.some(t => t.toLowerCase().includes(c)))) {
                resolve({
                  domain: domain,
                  category: category,
                  confidence: 0.95,
                  isBlocked: true,
                  source: 'api'
                })
                return
              }
            }

            resolve({
              domain: domain,
              category: 'uncategorized',
              confidence: 0,
              isBlocked: false,
              source: 'api'
            })
          } catch (error) {
            resolve({
              domain: domain,
              category: 'uncategorized',
              confidence: 0,
              isBlocked: false,
              source: 'timeout'
            })
          }
        })
      })

      req.on('error', () => {
        resolve({
          domain: domain,
          category: 'uncategorized',
          confidence: 0,
          isBlocked: false,
          source: 'timeout'
        })
      })

      req.on('timeout', () => {
        req.destroy()
        resolve({
          domain: domain,
          category: 'uncategorized',
          confidence: 0,
          isBlocked: false,
          source: 'timeout'
        })
      })

      req.end()
    })
  }

  static isBlockedCategory(category: string): boolean {
    return BLOCKED_CATEGORIES.includes(category.toLowerCase())
  }

  static getBlockedCategories(): string[] {
    return [...BLOCKED_CATEGORIES]
  }
}
