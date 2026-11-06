const path = require('path');

function exportFile(req, res) {
  const file = path.join('/data', req.query.name);
  res.sendFile(file);
}

function other() {
  return 1;
}
