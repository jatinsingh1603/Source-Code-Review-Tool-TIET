'use strict';

const fs = require('fs');
const path = require('path');
const config = require('./config');

function exportStatement(req, res) {
  const file = path.join(config.exportDir, req.query.file);
  fs.createReadStream(file).pipe(res);
}

function exportStatementSafely(req, res) {
  const root = path.resolve(config.exportDir);
  const resolved = path.resolve(root, req.query.file);
  if (!resolved.startsWith(root + path.sep)) {
    res.status(400).send('unknown statement');
    return;
  }
  fs.createReadStream(resolved).pipe(res);
}

module.exports = { exportStatement, exportStatementSafely };
