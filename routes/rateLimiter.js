const rateLimit = require('express-rate-limit');
const { authenticate, authorize } = require('../middleware/deviceLock');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20,
  message: 'Too many attempts from this IP, please try again later.'
});

module.exports = { authLimiter };