import { LatencyAnalysis } from '../types';

const latencyThresholds = {
  direct: 500,
  proxy: 1500,
  vpn: 2000,
  tor: 5000
};

const baselineLatencies = new Map<string, number>([
  ['google.com', 100],
  ['cloudflare.com', 50],
  ['amazon.com', 150],
  ['microsoft.com', 120],
  ['facebook.com', 80]
]);

export function analyzeLatency(requestTimestamp?: number, responseTimestamp?: number, targetUrl?: string): LatencyAnalysis {
  let latencyAnomaly = false;
  let latencyMs = 0;
  let threshold = latencyThresholds.direct;
  let score = 0;

  if (requestTimestamp && responseTimestamp) {
    latencyMs = responseTimestamp - requestTimestamp;
    
    if (targetUrl) {
      try {
        const hostname = new URL(targetUrl).hostname;
        const baseline = baselineLatencies.get(hostname) || 200;
        
        if (latencyMs > baseline * 3) {
          latencyAnomaly = true;
          score += 30;
        } else if (latencyMs > baseline * 2) {
          score += 15;
        }
      } catch (error) {
        if (latencyMs > latencyThresholds.direct) {
          latencyAnomaly = true;
          score += 20;
        }
      }
    } else {
      if (latencyMs > latencyThresholds.direct) {
        latencyAnomaly = true;
        score += 25;
      }
    }

    if (latencyMs > latencyThresholds.proxy) {
      threshold = latencyThresholds.proxy;
      score += 20;
    }
    
    if (latencyMs > latencyThresholds.vpn) {
      threshold = latencyThresholds.vpn;
      score += 15;
    }
    
    if (latencyMs > latencyThresholds.tor) {
      threshold = latencyThresholds.tor;
      score += 25;
    }

    if (latencyMs < 10) {
      score += 10;
    }

    if (latencyMs > 30000) {
      latencyAnomaly = true;
      score += 35;
    }

  } else {
    score = 10;
  }

  return {
    latencyAnomaly,
    latencyMs,
    threshold,
    score: Math.min(score, 100)
  };
}
