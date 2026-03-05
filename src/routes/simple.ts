import { Request, Response } from 'express';
import { analyzeHeaders } from '../modules/headerDetector';
import { analyzeTLS } from '../modules/tlsDetector';
import { analyzeIP } from '../modules/ipDetector';
import { analyzeLatency } from '../modules/latencyDetector';
import { calculateRiskScore, determineProxyDetection } from '../modules/riskScorer';
import { isBlockedURL } from '../modules/urlBlocker';
import { DetectionRequest } from '../types';

export async function handleSimpleDetection(req: Request, res: Response): Promise<void> {
  const { url, headers, ja3Fingerprint, tlsVersion, cipherSuite, clientIP, requestTimestamp, responseTimestamp } = req.body as DetectionRequest;

  if (!url) {
    res.status(400).json({ error: 'URL is required' });
    return;
  }

  const blockResult = isBlockedURL(url);
  if (blockResult.blocked) {
    res.json({ url, proxy: true, blocked: true, reason: blockResult.reason });
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

  res.json({ url, proxy: proxyDetected });
}
