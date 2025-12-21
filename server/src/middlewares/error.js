export const notFound = (req, res, next) => {
  res.status(404).json({ success: false, message: 'Route not found' });
};

export const errorHandler = (err, req, res, next) => {
  const status = err.status || 500;
  const message = err.message || 'Internal Server Error';
  res.status(status).json({ success: false, message });
};
