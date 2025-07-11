/**
 * @swagger
 * tags:
 *   name: Lessons
 *   description: Manage lessons
 */
const express = require('express');
const router = express.Router();
const pool = require('../db');
const { authenticate, authorize } = require('../middleware/auth');

// add lesson
router.post('/chapters/:chapterId/lessons', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const { chapterId } = req.params;
    const { title, video_link, order } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO lessons (chapter_id,title,video_link,order_index) VALUES ($1,$2,$3,$4) RETURNING *',
      [chapterId, title, video_link, order || 0]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// update lesson
router.put('/lessons/:id', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    const { title, video_link, order } = req.body;
    const { rows } = await pool.query(
      'UPDATE lessons SET title=$1, video_link=$2, order_index=$3 WHERE id=$4 RETURNING *',
      [title, video_link, order, id]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// delete lesson
router.delete('/lessons/:id', authenticate, authorize('admin'), async (req, res, next) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM lessons WHERE id=$1', [id]);
    res.sendStatus(204);
  } catch (err) { next(err); }
});

module.exports = router;