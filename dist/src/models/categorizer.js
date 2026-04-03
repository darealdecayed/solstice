"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Categorizer = exports.Category = void 0;
var Category;
(function (Category) {
    Category["SAFE"] = "safe";
    Category["GAMING"] = "gaming";
    Category["PROXY"] = "proxy";
    Category["SOCIAL_MEDIA"] = "social_media";
    Category["LLM"] = "llm";
    Category["SELF_HARM"] = "self_harm";
    Category["ADULT"] = "adult";
    Category["EDUCATIONAL"] = "educational";
    Category["NEWS"] = "news";
    Category["SHOPPING"] = "shopping";
    Category["STREAMING"] = "streaming";
})(Category || (exports.Category = Category = {}));
class Categorizer {
    static async categorizeDomain(domain, content) {
        const results = [];
        results.push(await this.checkLLMSite(domain, content));
        results.push(await this.checkGamingSite(domain, content));
        results.push(await this.checkProxySite(domain, content));
        results.push(await this.checkSocialMedia(domain, content));
        results.push(await this.checkSelfHarm(domain, content));
        results.push(await this.checkAdultContent(domain, content));
        results.push(await this.checkEducational(domain, content));
        results.push(await this.checkNews(domain, content));
        results.push(await this.checkShopping(domain, content));
        results.push(await this.checkStreaming(domain, content));
        results.sort((a, b) => b.confidence - a.confidence);
        return results[0] || { category: Category.SAFE, confidence: 0, reasons: [] };
    }
    static async checkLLMSite(domain, content) {
        const reasons = [];
        let confidence = 0;
        const llmIndicators = [
            /chat\.(gpt|openai|anthropic|claude|gemini|bard|bing)/i,
            /(openai|anthropic|claude|gemini|chatgpt)\.com/i,
            /(huggingface|replicate|runway|midjourney|stability)\.ai/i,
            /(character\.ai|candy\.ai|poe\.com|perplexity\.ai)/i,
            /(groq|together|fireworks|cohere)\.ai/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        llmIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.8;
                reasons.push(`LLM pattern match: ${pattern.source}`);
            }
        });
        const llmKeywords = [
            'artificial intelligence', 'machine learning', 'large language model',
            'neural network', 'deep learning', 'natural language processing',
            'text generation', 'ai assistant', 'conversational ai',
            'language model', 'prompt engineering', 'ai chat'
        ];
        llmKeywords.forEach(keyword => {
            if (contentLower.includes(keyword)) {
                confidence += 0.3;
                reasons.push(`LLM keyword found: ${keyword}`);
            }
        });
        return { category: Category.LLM, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkGamingSite(domain, content) {
        const reasons = [];
        let confidence = 0;
        const gamingIndicators = [
            /(game|games|gaming|play|arcade|puzzle|action|adventure|strategy|rpg|mmo|fps)/i,
            /(roblox|minecraft|fortnite|valorant|league|csgo|dota|wow|overwatch)/i,
            /(steam|epicgames|origin|uplay|battle\.net|xbox|playstation)/i,
            /(twitch|youtube\.com\/gaming|gaming\.youtube|discord\.com\/channels)/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        gamingIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.7;
                reasons.push(`Gaming pattern match: ${pattern.source}`);
            }
        });
        const interactiveElements = (contentLower.match(/<iframe|<embed|<object|<canvas|<game|<play/gi) || []).length;
        if (interactiveElements > 5) {
            confidence += 0.4;
            reasons.push('High interactive element count');
        }
        return { category: Category.GAMING, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkProxySite(domain, content) {
        const reasons = [];
        let confidence = 0;
        const proxyIndicators = [
            /(proxy|vpn|tunnel|bypass|unblock|cloak|hide)/i,
            /(ultraviolet|rammerhead|bare-mux|wisp|corrosion)/i,
            /(titaniumnetwork|mercuryworkshop|ltbeef|ltmeat)/i,
            /(herokuapp|netlify|vercel|glitch|replit).*proxy/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        proxyIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.8;
                reasons.push(`Proxy pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.PROXY, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkSocialMedia(domain, content) {
        const reasons = [];
        let confidence = 0;
        const socialIndicators = [
            /(facebook|instagram|twitter|x\.com|linkedin|tiktok|snapchat)/i,
            /(reddit|discord|telegram|whatsapp|signal|mastodon)/i,
            /(youtube|vimeo|dailymotion|twitch|kick)/i,
            /(pinterest|tumblr|medium|substack)/i
        ];
        const domainLower = domain.toLowerCase();
        socialIndicators.forEach(pattern => {
            if (pattern.test(domainLower)) {
                confidence += 0.9;
                reasons.push(`Social media pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.SOCIAL_MEDIA, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkSelfHarm(domain, content) {
        const reasons = [];
        let confidence = 0;
        const harmfulIndicators = [
            /(suicide|self-harm|self-injury|cutting|self-harm)/i,
            /(depression|anxiety|eating-disorder|self-helpline)/i,
            /(pro-ana|pro-mia|thinspiration|self-harm)/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        harmfulIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.9;
                reasons.push(`Self-harm pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.SELF_HARM, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkAdultContent(domain, content) {
        const reasons = [];
        let confidence = 0;
        const adultIndicators = [
            /(porn|xxx|adult|sex|nude|naked|erotic)/i,
            /(onlyfans|fansly|patreon|adultfriendfinder)/i,
            /(nsfw|18\+|adult-content|mature)/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        adultIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.9;
                reasons.push(`Adult content pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.ADULT, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkEducational(domain, content) {
        const reasons = [];
        let confidence = 0;
        const eduIndicators = [
            /(edu|education|learning|academic|university|college|school)/i,
            /(khan|coursera|udemy|edx|skillshare|pluralsight)/i,
            /(wikipedia|britannica|nationalgeographic|discovery)/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        eduIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.7;
                reasons.push(`Educational pattern match: ${pattern.source}`);
            }
        });
        const eduKeywords = [
            'lesson', 'course', 'tutorial', 'study', 'learn', 'education',
            'academic', 'research', 'curriculum', 'classroom', 'student'
        ];
        eduKeywords.forEach(keyword => {
            if (contentLower.includes(keyword)) {
                confidence += 0.2;
                reasons.push(`Educational keyword found: ${keyword}`);
            }
        });
        return { category: Category.EDUCATIONAL, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkNews(domain, content) {
        const reasons = [];
        let confidence = 0;
        const newsIndicators = [
            /(news|cnn|bbc|reuters|associated-press|washington-post)/i,
            /(nytimes|wsj|ft|economist|time|newsweek)/i,
            /(huffpost|vice|buzzfeed|vox|salon)/i
        ];
        const domainLower = domain.toLowerCase();
        newsIndicators.forEach(pattern => {
            if (pattern.test(domainLower)) {
                confidence += 0.8;
                reasons.push(`News pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.NEWS, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkShopping(domain, content) {
        const reasons = [];
        let confidence = 0;
        const shopIndicators = [
            /(amazon|ebay|walmart|target|bestbuy|shop)/i,
            /(etsy|shopify|bigcommerce|magento|woocommerce)/i,
            /(buy|purchase|cart|checkout|order|shipping)/i
        ];
        const domainLower = domain.toLowerCase();
        const contentLower = content?.toLowerCase() || '';
        shopIndicators.forEach(pattern => {
            if (pattern.test(domainLower) || pattern.test(contentLower)) {
                confidence += 0.7;
                reasons.push(`Shopping pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.SHOPPING, confidence: Math.min(confidence, 1), reasons };
    }
    static async checkStreaming(domain, content) {
        const reasons = [];
        let confidence = 0;
        const streamIndicators = [
            /(netflix|hulu|disney\+|hbo|max|prime-video)/i,
            /(youtube|vimeo|dailymotion|twitch|kick)/i,
            /(spotify|apple-music|tidal|pandora|soundcloud)/i
        ];
        const domainLower = domain.toLowerCase();
        streamIndicators.forEach(pattern => {
            if (pattern.test(domainLower)) {
                confidence += 0.8;
                reasons.push(`Streaming pattern match: ${pattern.source}`);
            }
        });
        return { category: Category.STREAMING, confidence: Math.min(confidence, 1), reasons };
    }
}
exports.Categorizer = Categorizer;
//# sourceMappingURL=categorizer.js.map