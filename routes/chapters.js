/**
 * @swagger
 * tags:
 *   name: Chapters
 *   description: Manage chapters
 */
const express = require('express');
const router = express.Router();
const pool = require('../db');
const { authenticate, authorize } = require('../middleware/auth');
const { deviceLock } = require('../middleware/deviceLock');


// create chapter
router.post('/:courseId/chapters', authenticate, authorize('admin'),  deviceLock, async (req, res, next) => {
  try {
    const { courseId } = req.params;
    const { title, order } = req.body;
    const { rows } = await pool.query(
      'INSERT INTO chapters (course_id,title,order_index) VALUES ($1,$2,$3) RETURNING *',
      [courseId, title, order || 0]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// update chapter
router.put('/chapters/:id', authenticate, authorize('admin'), deviceLock, async (req, res, next) => {
  try {
    const { id } = req.params;
    const { title, order } = req.body;
    const { rows } = await pool.query(
      'UPDATE chapters SET title=$1, order_index=$2 WHERE id=$3 RETURNING *',
      [title, order, id]
    );
    res.json(rows[0]);
  } catch (err) { next(err); }
});

// delete chapter
router.delete('/chapters/:id', authenticate, authorize('admin'), deviceLock, async (req, res, next) => {
  try {
    const { id } = req.params;
    await pool.query('DELETE FROM chapters WHERE id=$1', [id]);
    res.sendStatus(204);
  } catch (err) { next(err); }
});

module.exports = router;