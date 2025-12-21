import { ZodError } from 'zod';

export const validate = (schema) => (req, res, next) => {
  try {
    if (!schema) return next();
    const data = ['GET', 'DELETE'].includes(req.method) ? req.query : req.body;
    schema.parse(data);
    next();
  } catch (err) {
    if (err instanceof ZodError) {
      const first = err.errors?.[0];
      return res.status(400).json({ success: false, message: first?.message || 'Invalid input' });
    }
    next(err);
  }
};
