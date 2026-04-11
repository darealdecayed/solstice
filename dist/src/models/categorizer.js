"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Categorizer = void 0;
const https_1 = __importDefault(require("https"));
const BLOCKED_CATEGORIES = ['adult', 'pornography', 'adult-content', 'nsfw'];
class Categorizer {
    async categorize(domain) {
        const cleanDomain = domain.replace(/^www\./, '');
        const result = await Promise.race([
            this.queryURLhaus(cleanDomain),
            new Promise(resolve => setTimeout(() => resolve({
                domain: cleanDomain,
                category: 'uncategorized',
                confidence: 0,
                isBlocked: false,
                source: 'timeout'
            }), 3000))
        ]);
        return result;
    }
    queryURLhaus(domain) {
        return new Promise((resolve) => {
            const options = {
                hostname: 'urlhaus-api.abuse.ch',
                path: `/v1/urls/on_host/?host=${encodeURIComponent(domain)}`,
                method: 'GET',
                timeout: 2500
            };
            const req = https_1.default.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });
                res.on('end', () => {
                    try {
                        const json = JSON.parse(data);
                        if (json.urls && json.urls.length > 0) {
                            const urls = json.urls;
                            const threatData = urls[0];
                            const category = threatData.threat?.toLowerCase() || 'unknown';
                            const tags = threatData.tags || [];
                            if (BLOCKED_CATEGORIES.some(c => category.includes(c) || tags.some(t => t.toLowerCase().includes(c)))) {
                                resolve({
                                    domain: domain,
                                    category: category,
                                    confidence: 0.95,
                                    isBlocked: true,
                                    source: 'api'
                                });
                                return;
                            }
                        }
                        resolve({
                            domain: domain,
                            category: 'uncategorized',
                            confidence: 0,
                            isBlocked: false,
                            source: 'api'
                        });
                    }
                    catch (error) {
                        resolve({
                            domain: domain,
                            category: 'uncategorized',
                            confidence: 0,
                            isBlocked: false,
                            source: 'timeout'
                        });
                    }
                });
            });
            req.on('error', () => {
                resolve({
                    domain: domain,
                    category: 'uncategorized',
                    confidence: 0,
                    isBlocked: false,
                    source: 'timeout'
                });
            });
            req.on('timeout', () => {
                req.destroy();
                resolve({
                    domain: domain,
                    category: 'uncategorized',
                    confidence: 0,
                    isBlocked: false,
                    source: 'timeout'
                });
            });
            req.end();
        });
    }
    static isBlockedCategory(category) {
        return BLOCKED_CATEGORIES.includes(category.toLowerCase());
    }
    static getBlockedCategories() {
        return [...BLOCKED_CATEGORIES];
    }
}
exports.Categorizer = Categorizer;
//# sourceMappingURL=categorizer.js.map