export interface DetectionRequest {
  url: string;
  headers?: Record<string, string>;
  ja3Fingerprint?: string;
  tlsVersion?: string;
  cipherSuite?: string;
  clientIP?: string;
  requestTimestamp?: number;
  responseTimestamp?: number;
  userAgent?: string;
}

export interface HeaderAnalysis {
  suspiciousHeaders: string[];
  viaHeader: boolean;
  xForwardedFor: boolean;
  forwardedHeader: boolean;
  proxyConnection: boolean;
  score: number;
}

export interface TLSAnalysis {
  ja3Mismatch: boolean;
  tlsVersionAnomaly: boolean;
  cipherSuiteAnomaly: boolean;
  score: number;
}

export interface IPReputation {
  isProxy: boolean;
  isVPN: boolean;
  isTor: boolean;
  isMalicious: boolean;
  reputation: number;
  score: number;
}

export interface LatencyAnalysis {
  latencyAnomaly: boolean;
  latencyMs: number;
  threshold: number;
  score: number;
}

export interface DetectionResult {
  url: string;
  timestamp: number;
  riskScore: number;
  proxyDetected: boolean;
  signals: {
    headers: HeaderAnalysis;
    tls: TLSAnalysis;
    ip: IPReputation;
    latency: LatencyAnalysis;
  };
  blocked: boolean;
  blockReason?: string;
}

export interface RiskWeights {
  headers: number;
  tls: number;
  ip: number;
  latency: number;
}
