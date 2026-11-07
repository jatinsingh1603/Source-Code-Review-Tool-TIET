const express = require('express');
const router = express.Router();

router.get('/items/:id', (req, res) => {
  res.json({ id: req.params.id, note: req.query.note });
});
