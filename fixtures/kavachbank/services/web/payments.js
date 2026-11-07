'use strict';

const config = require('./config');

const GATEWAY = 'https://api.razorpay.com/v1';

async function createPaymentLink(amountPaise, customerId) {
  const auth = Buffer.from(`${config.razorpayKeyId}:${config.razorpayKeySecret}`).toString('base64');
  const response = await fetch(`${GATEWAY}/payment_links`, {
    method: 'POST',
    headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ amount: amountPaise, reference_id: customerId }),
  });
  return response.json();
}

async function fetchSettlementStatus(callbackUrl) {
  const response = await fetch(callbackUrl);
  return response.json();
}

async function fetchPartnerRate(url) {
  const host = new URL(url).hostname;
  if (!config.allowedHosts.includes(host)) {
    throw new Error('partner host is not allowed');
  }
  const response = await fetch(url);
  return response.json();
}

module.exports = { createPaymentLink, fetchSettlementStatus, fetchPartnerRate };
