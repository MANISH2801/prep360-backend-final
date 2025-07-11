
/**
 * @swagger
 * tags:
 *   name: 2FA
 *   description: Two‑factor authentication endpoints
 */
// routes/totp.js
const express = require('express');
const { authenticate, authorize } = require('middleware/auth');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');
const pool = require('../db');

const router = express.Router();

/**
 * POST /auth/2fa/setup
 * Generates a secret & QR for Google Authenticator.
 */
router.post('/setup', async (req, res) => {
  const secret = speakeasy.generateSecret({
    name: `Prep360 (${req.user.email})`
  });

  await pool.query(
    'UPDATE users SET totp_secret=$1, totp_enabled=false WHERE id=$2',
    [secret.base32, req.user.id]
  );

  const otpauth = secret.otpauth_url;
  const qrDataUrl = await QRCode.toDataURL(otpauth);

  res.json({ otpauth, qrDataUrl });
});

/**
 * POST /auth/2fa/verify
 * Body: { token }
 */
router.post('/verify', async (req, res) => {
  const { token } = req.body;
  if (!token) return res.status(400).json({ error: 'Token required' });

  const { rows } = await pool.query(
    'SELECT totp_secret FROM users WHERE id=$1',
    [req.user.id]
  );
  const secret = rows[0]?.totp_secret;
  if (!secret) return res.status(400).json({ error: 'No secret set' });

  const verified = speakeasy.totp.verify({
    secret,
    encoding: 'base32',
    token
  });

  if (!verified) return res.status(401).json({ error: 'Invalid token' });

  await pool.query('UPDATE users SET totp_enabled=true WHERE id=$1', [req.user.id]);
  res.json({ message: '2FA enabled ✅' });
});

module.exports = router;