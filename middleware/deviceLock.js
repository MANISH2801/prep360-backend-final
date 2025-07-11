// middleware/deviceLock.js
const pool = require('../db');

/**
 * Middleware to enforce single-device login.
 * Expects 'x-device-id' header set by the client.
 */
async function deviceLock(req, res, next) {
  try {
    const deviceId = req.headers['x-device-id'];
    if (!deviceId) return res.status(400).json({ error: 'Missing x-device-id header' });

    const { rows } = await pool.query('SELECT device_id FROM users WHERE id=$1', [req.user.id]);
    if (!rows.length) return res.status(401).json({ error: 'User not found' });

    const current = rows[0].device_id;
    if (current && current !== deviceId) {
      return res.status(403).json({ error: 'Another device is already logged in' });
    }

    // Store device ID if not set
    if (!current) {
      await pool.query('UPDATE users SET device_id=$1 WHERE id=$2', [deviceId, req.user.id]);
    }
    next();
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Device lock failed' });
  }
}

module.exports = deviceLock;
