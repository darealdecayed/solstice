import { HeaderAnalysis } from '../types';

const suspiciousHeaderPatterns = [
  /^via$/i,
  /^x-forwarded-for$/i,
  /^x-forwarded-host$/i,
  /^x-forwarded-proto$/i,
  /^x-forwarded-server$/i,
  /^x-real-ip$/i,
  /^x-proxy-user-ip$/i,
  /^proxy-connection$/i,
  /^forwarded$/i,
  /^x-cdn-id$/i,
  /^x-cluster-client-ip$/i,
  /^cf-connecting-ip$/i,
  /^x-original-url$/i,
  /^x-rewrite-url$/i,
  /^x-gateway$/i,
  /^x-forwarded$/i
];

const knownProxyValues = [
  'squid',
  'nginx',
  'apache',
  'varnish',
  'cloudflare',
  'fastly',
  'akamai',
  'edge',
  'proxy',
  'gateway',
  'cache'
];

export function analyzeHeaders(headers: Record<string, string>): HeaderAnalysis {
  const suspiciousHeaders: string[] = [];
  let viaHeader = false;
  let xForwardedFor = false;
  let forwardedHeader = false;
  let proxyConnection = false;

  Object.entries(headers).forEach(([key, value]) => {
    const lowerKey = key.toLowerCase();
    
    if (suspiciousHeaderPatterns.some(pattern => pattern.test(lowerKey))) {
      suspiciousHeaders.push(key);
      
      if (lowerKey === 'via') viaHeader = true;
      if (lowerKey === 'x-forwarded-for') xForwardedFor = true;
      if (lowerKey === 'forwarded') forwardedHeader = true;
      if (lowerKey === 'proxy-connection') proxyConnection = true;
      
      const lowerValue = value.toLowerCase();
      if (knownProxyValues.some(proxy => lowerValue.includes(proxy))) {
        suspiciousHeaders.push(`${key}: ${value}`);
      }
    }
  });

  const baseScore = suspiciousHeaders.length * 15;
  const proxyIndicators = [viaHeader, xForwardedFor, forwardedHeader, proxyConnection].filter(Boolean).length;
  const score = Math.min(baseScore + (proxyIndicators * 10), 100);

  return {
    suspiciousHeaders,
    viaHeader,
    xForwardedFor,
    forwardedHeader,
    proxyConnection,
    score
  };
}
