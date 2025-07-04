// server.js
// Simple Express server for Prep360 backend

const express = require('express');
const app = express();

// ───────────────────────── Routes ─────────────────────────
app.get('/', (req, res) => {
  res.send('Prep360 backend is running ✅');
});

// ───────────────────────── Server ─────────────────────────
const PORT = process.env.PORT || 3000;   // Render injects PORT
app.listen(PORT, () => {
  console.log(`🚀  Server listening on port ${PORT}`);
});
