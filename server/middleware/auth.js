import jwt from 'jsonwebtoken';
import sanitize from 'mongo-sanitize';

export const requireAuth = (req, res, next) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) {
      return res.status(401).json({ success: false, message: 'Unauthorized' });
    }
    const payload = jwt.verify(token, process.env.JWT_ACCESS_SECRET);
    req.user = { id: payload.id };
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Invalid or expired token' });
  }
};

export const getClientInfo = (req) => ({
  userAgent: sanitize(req.headers['user-agent'] || ''),
  ip: (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString()
});
