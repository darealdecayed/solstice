export interface CategoryResult {
    domain: string;
    category: string;
    confidence: number;
    isBlocked: boolean;
    source: 'api' | 'timeout';
}
export declare class Categorizer {
    categorize(domain: string): Promise<CategoryResult>;
    private queryURLhaus;
    static isBlockedCategory(category: string): boolean;
    static getBlockedCategories(): string[];
}
//# sourceMappingURL=categorizer.d.ts.map