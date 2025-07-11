// middleware/auth.js
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'fallbackSecret';

/** Verify JWT and attach user to req.user */
function authenticate(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.replace(/^Bearer\s+/i, '');

  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    req.user = jwt.verify(token, JWT_SECRET); // { id, user_type, ... }
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid / expired token' });
  }
}

/** Allow only users whose user_type matches one of the allowedRoles */
function authorize(...allowedRoles) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthenticated' });

    if (!allowedRoles.includes(req.user.user_type)) {
      return res.status(403).json({ error: 'Forbidden: insufficient role' });
    }
    next();
  };
}

module.exports = { authenticate, authorize };
