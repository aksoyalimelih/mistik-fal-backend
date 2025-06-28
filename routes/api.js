const express = require('express');
const router = express.Router();

// Örnek endpoint
router.get('/test', (req, res) => {
  res.json({ message: 'API çalışıyor!' });
});

module.exports = router;