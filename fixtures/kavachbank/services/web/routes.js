'use strict';

const express = require('express');
const { requireSession } = require('./session');
const { renderGreeting, renderGreetingSafely } = require('./renderer');
const { exportStatement, exportStatementSafely } = require('./exporter');
const { createPaymentLink, fetchSettlementStatus, fetchPartnerRate } = require('./payments');

const router = express.Router();

router.get('/health', (req, res) => res.json({ status: 'ok' }));

router.get('/greeting', renderGreeting);
router.get('/greeting/safe', renderGreetingSafely);

router.get('/accounts/:id/export', requireSession, exportStatement);
router.get('/accounts/:id/export/safe', requireSession, exportStatementSafely);

router.post('/accounts/:id/payment-links', requireSession, async (req, res) => {
  res.json(await createPaymentLink(req.body.amountPaise, req.params.id));
});

router.get('/payments/status', requireSession, async (req, res) => {
  res.json(await fetchSettlementStatus(req.query.callback));
});

router.get('/rates', requireSession, async (req, res) => {
  res.json(await fetchPartnerRate(req.query.partner));
});

module.exports = router;
