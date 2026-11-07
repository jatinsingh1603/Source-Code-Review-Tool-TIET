'use strict';

// DELIBERATELY INSECURE SAMPLE: the credentials below are synthetic and are listed in
// ground-truth/manifest.yaml. Nothing here is a working secret.

module.exports = {
  exportDir: process.env.KB_EXPORT_DIR || '/var/lib/kavachbank/exports',
  allowedHosts: ['rates.partner-bank.example', 'kyc.partner-bank.example'],
  sessionTtlMinutes: 30,
  razorpayKeyId: 'rzp_test_abcdefghijklmn',
  razorpayKeySecret: 'abcdefghijklmnopqrstuvwx',
};
