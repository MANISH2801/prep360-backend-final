// middleware/auth.js
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

function auth(req, res, next) {
  const hdr = req.headers.authorization || '';
  const token = hdr.replace(/^Bearer\s+/i, '');

  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    req.user = jwt.verify(token, JWT_SECRET); // Contains id, role, etc.
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid / expired token' });
  }
}

module.exports = auth;
