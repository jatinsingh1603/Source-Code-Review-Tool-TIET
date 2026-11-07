'use strict';

const crypto = require('crypto');
const config = require('./config');

const sessions = new Map();

function createSession(userId) {
  const id = crypto.randomBytes(24).toString('hex');
  sessions.set(id, { userId, expiresAt: Date.now() + config.sessionTtlMinutes * 60 * 1000 });
  return id;
}

function lookupSession(id) {
  const session = sessions.get(id);
  if (!session || session.expiresAt < Date.now()) {
    sessions.delete(id);
    return null;
  }
  return session;
}

function requireSession(req, res, next) {
  const session = lookupSession(req.get('x-session-id'));
  if (!session) {
    res.status(401).json({ error: 'sign in again' });
    return;
  }
  req.session = session;
  next();
}

module.exports = { createSession, lookupSession, requireSession };
