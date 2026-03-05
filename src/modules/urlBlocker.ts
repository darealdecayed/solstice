export function isBlockedURL(url: string): { blocked: boolean; reason?: string } {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    if (hostname.includes('freedns.afraid.org') || hostname.endsWith('.freedns.afraid.org')) {
      return { blocked: true, reason: 'Blocked freedns.afraid.org domain' };
    }

    const blockedDomains = [
      'freedns.afraid.org',
      'afraid.org'
    ];

    if (blockedDomains.some(domain => hostname === domain || hostname.endsWith('.' + domain))) {
      return { blocked: true, reason: 'Blocked domain' };
    }

    const suspiciousPatterns = [
      /.*\.tk$/,
      /.*\.ml$/,
      /.*\.ga$/,
      /.*\.cf$/,
      /.*\.bit$/,
      /.*\.onion$/,
      /proxy.*\.*/,
      /.*proxy.*/,
      /.*vpn.*/,
      /.*tunnel.*/,
      /.*gateway.*/
    ];

    if (suspiciousPatterns.some(pattern => pattern.test(hostname))) {
      return { blocked: true, reason: 'Suspicious domain pattern' };
    }

    return { blocked: false };
  } catch (error) {
    return { blocked: true, reason: 'Invalid URL format' };
  }
}
