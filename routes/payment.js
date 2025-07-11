/**
 * @swagger
 * tags:
 *   name: Payments
 *   description: Payment and order handling
 */
const express = require('express');
const { authenticate, authorize } = require('middleware/auth');
const router = express.Router();
const pool = require('../db');
const crypto = require('crypto');
const stripe = require('stripe')(process.env.STRIPE_SECRET || '');

/**
 * POST /payments/create-intent
 * Creates a payment intent for Stripe
 */
router.post('/create-intent', async (req, res, next) => {
  try {
    const { amount, currency = 'inr', course_id } = req.body;
    const intent = await stripe.paymentIntents.create({
      amount,
      currency,
      metadata: { course_id }
    });
    res.json({ clientSecret: intent.client_secret });
  } catch (err) {
    next(err);
  }
});

/**
 * POST /payments/webhook
 * Stripe webhook endpoint to confirm payment
 */
router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res, next) => {
  const sig = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  if (event.type === 'payment_intent.succeeded') {
    const intent = event.data.object;
    const courseId = intent.metadata.course_id;
    const userId = intent.metadata.user_id;
    // create order
    await pool.query(
      'INSERT INTO orders (user_id, course_id, amount, status) VALUES ($1,$2,$3,$4)',
      [userId, courseId, intent.amount, 'succeeded']
    );
    // enroll user
    await pool.query(
      'INSERT INTO enrollments (user_id, course_id) VALUES ($1,$2) ON CONFLICT DO NOTHING',
      [userId, courseId]
    );
  }
  res.json({ received: true });
});

module.exports = router;