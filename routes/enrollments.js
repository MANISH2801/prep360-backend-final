
/**
 * @swagger
 * tags:
 *   name: Enrollments
 *   description: Course enrollment endpoints
 */
// routes/enrollments.js
const express = require('express');
const { authenticate, authorize } = require('middleware/auth');
const pool = require('../db');
const sendMail = require('../utils/email');

const router = express.Router();

/**
 * POST /courses/:id/enroll
 */
router.post('/:id/enroll', async (req, res) => {
  const courseId = req.params.id;
  const userId = req.user.id;

  const existing = await pool.query(
    'SELECT 1 FROM enrollments WHERE user_id=$1 AND course_id=$2',
    [userId, courseId]
  );
  if (existing.rows.length) return res.status(409).json({ error: 'Already enrolled' });

  await pool.query(
    'INSERT INTO enrollments (user_id, course_id, enrolled_at) VALUES ($1,$2,NOW())',
    [userId, courseId]
  );
    // Send confirmation email
  const { rows: userRows } = await pool.query('SELECT email FROM users WHERE id=$1', [userId]);
  const { rows: courseRows } = await pool.query('SELECT title FROM courses WHERE id=$1', [courseId]);
  if (userRows.length && courseRows.length) {
    sendMail({
      to: userRows[0].email,
      subject: `Enrolled in ${courseRows[0].title}`,
      html: `<p>You have successfully enrolled in <strong>${courseRows[0].title}</strong>. Enjoy learning!</p>`
    }).catch(console.error);
  }
  res.json({ message: 'Enrolled ✅' });

});

module.exports = router;