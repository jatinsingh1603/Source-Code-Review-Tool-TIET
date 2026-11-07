const fs = require('fs');
const path = require('node:path');

function readConfig(name) {
  return fs.readFileSync(path.join(__dirname, name), 'utf8');
}
