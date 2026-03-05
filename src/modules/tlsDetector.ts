import { TLSAnalysis } from '../types';

const knownJA3Hashes = new Set([
  'b32309a26951912c65eea8d88d35a00c',
  'c8ade1051d639987f9d54ec9c6d126c3',
  'a771aa833d087c9bfd008e8a47f7927d',
  '6744cb1b6b5c6d4b5b5b5b5b5b5b5b5b',
  'f895c53b5b5c6d4b5b5b5b5b5b5b5b5b'
]);

const suspiciousTLSVersions = [
  'TLSv1.0',
  'SSLv3',
  'SSLv2'
];

const weakCipherSuites = [
  'RC4',
  'DES',
  '3DES',
  'MD5',
  'NULL',
  'EXPORT',
  'ADH',
  'AECDH'
];

export function analyzeTLS(ja3Fingerprint?: string, tlsVersion?: string, cipherSuite?: string): TLSAnalysis {
  let ja3Mismatch = false;
  let tlsVersionAnomaly = false;
  let cipherSuiteAnomaly = false;
  let score = 0;

  if (ja3Fingerprint) {
    ja3Mismatch = !knownJA3Hashes.has(ja3Fingerprint.toLowerCase());
    if (ja3Mismatch) score += 30;
  }

  if (tlsVersion) {
    tlsVersionAnomaly = suspiciousTLSVersions.some(version => 
      tlsVersion.toLowerCase().includes(version.toLowerCase())
    );
    if (tlsVersionAnomaly) score += 25;
  }

  if (cipherSuite) {
    const lowerCipher = cipherSuite.toLowerCase();
    cipherSuiteAnomaly = weakCipherSuites.some(weak => lowerCipher.includes(weak.toLowerCase()));
    if (cipherSuiteAnomaly) score += 20;
  }

  if (ja3Fingerprint && tlsVersion && cipherSuite) {
    if (ja3Mismatch && tlsVersionAnomaly) score += 15;
    if (ja3Mismatch && cipherSuiteAnomaly) score += 10;
  }

  return {
    ja3Mismatch,
    tlsVersionAnomaly,
    cipherSuiteAnomaly,
    score: Math.min(score, 100)
  };
}
