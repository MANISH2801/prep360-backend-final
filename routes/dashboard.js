
/**
 * @swagger
 * tags:
 *   name: AdminDashboard
 *   description: Admin dashboard statistics
 */
// routes/dashboard.js
const express = require('express');
const { authenticate, authorize } = require('middleware/auth');
const pool = require('../db');
const router = express.Router();

/**
 * GET /admin/dashboard
 * Admin only
 */
router.get('/', async (_req, res) => {
  const [{ rows: users }, { rows: courses }, { rows: enrollments }] = await Promise.all([
    pool.query('SELECT COUNT(*) FROM users'),
    pool.query('SELECT COUNT(*) FROM courses'),
    pool.query('SELECT COUNT(*) FROM enrollments')
  ]);

  res.json({
    users: Number(users[0].count),
    courses: Number(courses[0].count),
    enrollments: Number(enrollments[0].count)
  });
});

module.exports = router;