export interface CategoryResult {
    category: Category;
    confidence: number;
    reasons: string[];
}
export declare enum Category {
    SAFE = "safe",
    GAMING = "gaming",
    PROXY = "proxy",
    SOCIAL_MEDIA = "social_media",
    LLM = "llm",
    SELF_HARM = "self_harm",
    ADULT = "adult",
    EDUCATIONAL = "educational",
    NEWS = "news",
    SHOPPING = "shopping",
    STREAMING = "streaming"
}
export declare class Categorizer {
    static categorizeDomain(domain: string, content?: string): Promise<CategoryResult>;
    private static checkLLMSite;
    private static checkGamingSite;
    private static checkProxySite;
    private static checkSocialMedia;
    private static checkSelfHarm;
    private static checkAdultContent;
    private static checkEducational;
    private static checkNews;
    private static checkShopping;
    private static checkStreaming;
}
//# sourceMappingURL=categorizer.d.ts.map