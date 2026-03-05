import { Request, Response } from 'express';
import { analyzeHeaders } from '../modules/headerDetector';
import { analyzeTLS } from '../modules/tlsDetector';
import { analyzeIP } from '../modules/ipDetector';
import { analyzeLatency } from '../modules/latencyDetector';
import { calculateRiskScore, determineProxyDetection } from '../modules/riskScorer';
import { isBlockedURL } from '../modules/urlBlocker';
import { DetectionRequest, DetectionResult } from '../types';

export async function handleDetection(req: Request, res: Response): Promise<void> {
  const { url, headers, ja3Fingerprint, tlsVersion, cipherSuite, clientIP, requestTimestamp, responseTimestamp, userAgent } = req.body as DetectionRequest;

  if (!url) {
    res.status(400).json({ error: 'URL is required' });
    return;
  }

  const blockResult = isBlockedURL(url);
  if (blockResult.blocked) {
    const result: DetectionResult = {
      url,
      timestamp: Date.now(),
      riskScore: 100,
      proxyDetected: true,
      signals: {
        headers: { suspiciousHeaders: [], viaHeader: false, xForwardedFor: false, forwardedHeader: false, proxyConnection: false, score: 0 },
        tls: { ja3Mismatch: false, tlsVersionAnomaly: false, cipherSuiteAnomaly: false, score: 0 },
        ip: { isProxy: false, isVPN: false, isTor: false, isMalicious: false, reputation: 100, score: 0 },
        latency: { latencyAnomaly: false, latencyMs: 0, threshold: 500, score: 0 }
      },
      blocked: true,
      blockReason: blockResult.reason
    };
    res.json(result);
    return;
  }

  const headerAnalysis = analyzeHeaders(headers || {});
  const tlsAnalysis = analyzeTLS(ja3Fingerprint, tlsVersion, cipherSuite);
  const ipAnalysis = clientIP ? await analyzeIP(clientIP) : { isProxy: false, isVPN: false, isTor: false, isMalicious: false, reputation: 100, score: 0 };
  const latencyAnalysis = analyzeLatency(requestTimestamp, responseTimestamp, url);

  const baseResult = {
    url,
    timestamp: Date.now(),
    signals: {
      headers: headerAnalysis,
      tls: tlsAnalysis,
      ip: ipAnalysis,
      latency: latencyAnalysis
    }
  };

  const riskScore = calculateRiskScore(baseResult);
  const proxyDetected = determineProxyDetection(riskScore);

  const result: DetectionResult = {
    ...baseResult,
    riskScore,
    proxyDetected,
    blocked: false
  };

  res.json(result);
}
