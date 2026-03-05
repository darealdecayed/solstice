import { DetectionResult, RiskWeights } from '../types';

const defaultWeights: RiskWeights = {
  headers: 0.3,
  tls: 0.25,
  ip: 0.3,
  latency: 0.15
};

const riskThresholds = {
  low: 30,
  medium: 60,
  high: 80
};

export function calculateRiskScore(result: Omit<DetectionResult, 'riskScore' | 'proxyDetected' | 'blocked' | 'blockReason'>, weights: RiskWeights = defaultWeights): number {
  const headerScore = result.signals.headers.score * weights.headers;
  const tlsScore = result.signals.tls.score * weights.tls;
  const ipScore = result.signals.ip.score * weights.ip;
  const latencyScore = result.signals.latency.score * weights.latency;

  let totalScore = headerScore + tlsScore + ipScore + latencyScore;

  const signalCount = [
    result.signals.headers.score > 0,
    result.signals.tls.score > 0,
    result.signals.ip.score > 0,
    result.signals.latency.score > 0
  ].filter(Boolean).length;

  if (signalCount >= 3) {
    totalScore += 10;
  }

  if (result.signals.headers.viaHeader && result.signals.ip.isProxy) {
    totalScore += 15;
  }

  if (result.signals.tls.ja3Mismatch && result.signals.ip.isProxy) {
    totalScore += 20;
  }

  if (result.signals.latency.latencyAnomaly && result.signals.ip.isProxy) {
    totalScore += 15;
  }

  if (result.signals.headers.suspiciousHeaders.length > 3) {
    totalScore += 10;
  }

  return Math.min(Math.round(totalScore), 100);
}

export function determineProxyDetection(riskScore: number): boolean {
  return riskScore >= riskThresholds.medium;
}

export function getRiskLevel(riskScore: number): 'low' | 'medium' | 'high' | 'critical' {
  if (riskScore >= riskThresholds.high) return 'critical';
  if (riskScore >= riskThresholds.medium) return 'high';
  if (riskScore >= riskThresholds.low) return 'medium';
  return 'low';
}
