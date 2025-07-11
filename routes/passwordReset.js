
/**
 * @swagger
 * tags:
 *   name: PasswordReset
 *   description: Password reset endpoints
 */
// routes/passwordReset.js
const express = require('express');
const { authenticate, authorize } = require('middleware/auth');
const crypto = require('crypto');
const bcrypt = require('bcrypt');
const pool = require('../db');
const sendMail = require('../utils/email');

const router = express.Router();

/**
 * POST /auth/request-password-reset
 * Body: { email }
 */
router.post('/request-password-reset', async (req, res) => {
  const { email } = req.body;
  const { rows } = await pool.query('SELECT id FROM users WHERE email=$1', [email]);
  if (!rows.length) return res.status(404).json({ error: 'User not found' });

  const token = crypto.randomBytes(32).toString('hex');
  const expires = new Date(Date.now() + 1000 * 60 * 30); // 30 min

  await pool.query(
    'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1,$2,$3)',
    [rows[0].id, token, expires]
  );

  const link = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  await sendMail({
    to: email,
    subject: 'Prep360 Password Reset',
    html: `<p>Click <a href="${link}">here</a> to reset your password. This link expires in 30 minutes.</p>`
  });

  res.json({ message: 'Reset email sent' });
});

/**
 * POST /auth/reset-password
 * Body: { token, password }
 */
router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;
  if (!token || !password) return res.status(400).json({ error: 'Token & password required' });

  const { rows } = await pool.query(
    'SELECT user_id, expires_at FROM password_resets WHERE token=$1',
    [token]
  );
  if (!rows.length) return res.status(400).json({ error: 'Invalid token' });

  const { user_id, expires_at } = rows[0];
  if (new Date(expires_at) < new Date()) return res.status(400).json({ error: 'Token expired' });

  const hash = await bcrypt.hash(password, 10);
  await pool.query('UPDATE users SET password=$1 WHERE id=$2', [hash, user_id]);
  await pool.query('DELETE FROM password_resets WHERE token=$1', [token]);

  res.json({ message: 'Password reset successful' });
});

module.exports = router;