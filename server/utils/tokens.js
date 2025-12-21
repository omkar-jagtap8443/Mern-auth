import jwt from 'jsonwebtoken';
import crypto from 'crypto';

const toMs = (str) => {
  // simple parser for d/h/m values like '7d', '15m'
  const m = String(str).match(/^(\d+)([smhd])$/);
  if (!m) return 0;
  const n = parseInt(m[1], 10);
  const unit = m[2];
  switch (unit) {
    case 's': return n * 1000;
    case 'm': return n * 60 * 1000;
    case 'h': return n * 60 * 60 * 1000;
    case 'd': return n * 24 * 60 * 60 * 1000;
    default: return 0;
  }
};

export const createAccessToken = (userId) => {
  const ttl = process.env.ACCESS_TOKEN_TTL || '15m';
  return jwt.sign({ id: userId }, process.env.JWT_ACCESS_SECRET, { expiresIn: ttl });
};

export const createRefreshToken = (userId) => {
  const ttl = process.env.REFRESH_TOKEN_TTL || '7d';
  return jwt.sign({ id: userId, type: 'refresh' }, process.env.JWT_REFRESH_SECRET, { expiresIn: ttl });
};

export const verifyRefreshToken = (token) => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
};

export const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

export const cookieOptions = () => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: process.env.NODE_ENV === 'production' ? 'strict' : 'lax',
  maxAge: toMs(process.env.REFRESH_TOKEN_TTL || '7d')
});
