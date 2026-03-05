import axios from 'axios';
import { IPReputation } from '../types';

const proxyIPRanges = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '100.64.0.0/10'
];

const knownProxyHosts = [
  'proxy',
  'gateway',
  'nat',
  'firewall',
  'router',
  'load-balancer',
  'lb',
  'cdn',
  'cache'
];

function isPrivateIP(ip: string): boolean {
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4) return false;
  
  return (parts[0] === 10) ||
         (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
         (parts[0] === 192 && parts[1] === 168) ||
         (parts[0] === 127) ||
         (parts[0] === 169 && parts[1] === 254) ||
         (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127);
}

function extractHostnameFromIP(ip: string): string {
  const reverse = ip.split('.').reverse().join('.');
  return `${reverse}.in-addr.arpa`;
}

export async function analyzeIP(ip: string): Promise<IPReputation> {
  let isProxy = false;
  let isVPN = false;
  let isTor = false;
  let isMalicious = false;
  let reputation = 100;
  let score = 0;

  if (isPrivateIP(ip)) {
    isProxy = true;
    score += 40;
    reputation = 30;
  }

  const hostname = extractHostnameFromIP(ip);
  if (knownProxyHosts.some(proxy => hostname.includes(proxy))) {
    isProxy = true;
    score += 25;
    reputation = Math.max(reputation - 20, 0);
  }

  try {
    const response = await axios.get(`https://ipapi.co/${ip}/json/`, {
      timeout: 3000,
      headers: { 'User-Agent': 'Mozilla/5.0' }
    });

    const data = response.data;
    if (data.org) {
      const org = data.org.toLowerCase();
      if (knownProxyHosts.some(proxy => org.includes(proxy))) {
        isProxy = true;
        score += 30;
        reputation = Math.max(reputation - 25, 0);
      }
    }

    if (data.is_proxy) {
      isProxy = true;
      score += 35;
      reputation = Math.max(reputation - 30, 0);
    }

    if (data.is_vpn) {
      isVPN = true;
      score += 20;
      reputation = Math.max(reputation - 15, 0);
    }

    if (data.is_tor) {
      isTor = true;
      score += 25;
      reputation = Math.max(reputation - 20, 0);
    }

  } catch (error) {
    score += 10;
    reputation = Math.max(reputation - 10, 0);
  }

  try {
    const abuseResponse = await axios.get(`https://api.abuseipdb.com/api/v2/check`, {
      timeout: 3000,
      headers: {
        'Key': 'demo',
        'Accept': 'application/json'
      },
      params: { ipAddress: ip, maxAgeInDays: 90 }
    });

    if (abuseResponse.data.data.abuseConfidenceScore > 25) {
      isMalicious = true;
      score += 30;
      reputation = Math.max(reputation - 35, 0);
    }
  } catch (error) {
    
  }

  return {
    isProxy,
    isVPN,
    isTor,
    isMalicious,
    reputation: Math.max(reputation, 0),
    score: Math.min(score, 100)
  };
}
