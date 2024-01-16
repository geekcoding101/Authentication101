import crypto from 'crypto';

const secretKey = 'your_secret_key'; // Use a strong secret key

const base64UrlEncode = (str: Buffer): string => {
  return str.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
};

const sign = (header: string, payload: string, secret: string): string => {
  const signature = crypto.createHmac('SHA256', secret)
    .update(`${header}.${payload}`)
    .digest('base64');
  return base64UrlEncode(Buffer.from(signature));
};

export const generateAccessToken = (username: string): string => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { username, exp: Math.floor(Date.now() / 1000) + (15 * 60) }; // 15 minutes expiry
  const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
  const signature = sign(encodedHeader, encodedPayload, secretKey);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
};

export const generateRefreshToken = (username: string): string => {
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = { username, type: 'refresh', exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) }; // 7 days expiry
  const encodedHeader = base64UrlEncode(Buffer.from(JSON.stringify(header)));
  const encodedPayload = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
  const signature = sign(encodedHeader, encodedPayload, secretKey);
  return `${encodedHeader}.${encodedPayload}.${signature}`;
};

export const verifyToken = (token: string): any => {
  const [encodedHeader, encodedPayload, signature] = token.split('.');
  const verifiedSignature = sign(encodedHeader, encodedPayload, secretKey);
  if (verifiedSignature !== signature) {
    throw new Error('Invalid token');
  }
  return JSON.parse(Buffer.from(encodedPayload, 'base64').toString());
};
