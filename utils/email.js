// utils/email.js
const nodemailer = require('nodemailer');
require('dotenv').config();

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: process.env.EMAIL_SECURE === 'true',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

/**
 * Send an email.
 * @param {{to:string, subject:string, html:string}} param0
 */
async function sendMail({ to, subject, html }) {
  const info = await transporter.sendMail({
    from: `"Prep360" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    html
  });
  console.log('✉️  Email sent: %s', info.messageId);
}

module.exports = sendMail;
