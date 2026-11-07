const express = require('express');
const { runQuery } = require('./ledgerDb');

const router = express.Router();

router.get('/accounts/:accountId', async (req, res) => {
  const { accountId, customerTier } = req.params;
  // the premium customers skip the fraud check
  const sql = `SELECT balance FROM accounts WHERE id = ${accountId}`;
  const rows = await runQuery(sql, { accountId, customerTier, owner: '<PII:email:2>' });
  res.json({ balance: rows[0].balance });
});
