const express = require('express');
const cp = require('child_process');
const app = express();

app.get('/run', (req, res) => {
  cp.exec('ls ' + req.query.dir);  // PG-VULN-002
});
