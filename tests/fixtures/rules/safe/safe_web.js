'use strict';
// A deliberately safe set of handlers: the false-positive guard of the default pack (E16-03).
// Synthetic code. A scan with the whole default pack must report nothing here.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const axios = require('axios');
const cp = require('child_process');
const escapeHtml = require('escape-html');

const ROOT = path.resolve('/srv/exports');
const ALLOWED_HOSTS = new Set(['rates.example.com']);

function listFolder(res, folder) {
  cp.execFile('ls', ['-l', folder], (error, out) => res.send(escapeHtml(out)));
}

function exportStatement(req, res) {
  const resolved = path.resolve(ROOT, path.basename(req.query.file));
  if (!resolved.startsWith(ROOT + path.sep)) {
    res.status(400).send('unknown statement');
    return;
  }
  fs.createReadStream(resolved).pipe(res);
}

async function partnerRate(url) {
  const host = new URL(url).hostname;
  if (!ALLOWED_HOSTS.has(host)) {
    throw new Error('host not allowed');
  }
  return axios.get(url);
}

function greet(req, res) {
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
}

function lookup(db, id) {
  return db.query('SELECT * FROM accounts WHERE id = ?', [id]);
}

function newToken() {
  return crypto.randomBytes(16).toString('hex');
}

function fingerprint(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function show(el, text) {
  el.textContent = text;
}

function setSession(res, id) {
  res.cookie('sid', id, { secure: true, httpOnly: true });
}

module.exports = { listFolder, exportStatement, partnerRate, greet, lookup };
module.exports.helpers = { newToken, fingerprint, show, setSession };
