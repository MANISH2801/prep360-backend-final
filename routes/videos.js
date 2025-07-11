
/**
 * @swagger
 * tags:
 *   name: Videos
 *   description: Course video endpoints
 */
// routes/videos.js
const express = require('express');
const { authenticate, authorize } = require('middleware/auth');
const pool = require('../db');
const router = express.Router();

/**
 * GET /courses/:id/videos
 */
router.get('/:id/videos', async (req, res) => {
  const { id } = req.params;
  const { rows } = await pool.query(
    'SELECT id, title, url FROM videos WHERE course_id=$1 ORDER BY id',
    [id]
  );
  res.json(rows);
});

/**
 * POST /courses/:id/videos
 * Body: { title, url }
 * Admin only (assumes requireAdmin middleware before router)
 */
router.post('/:id/videos', async (req, res) => {
  const { id } = req.params;
  const { title, url } = req.body;
  await pool.query(
    'INSERT INTO videos (course_id, title, url) VALUES ($1,$2,$3)',
    [id, title, url]
  );
  res.status(201).json({ message: 'Video added' });
});

module.exports = router;