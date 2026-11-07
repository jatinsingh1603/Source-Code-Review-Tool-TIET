const crypto = require('crypto');

function digest(secret, message) {
  return crypto.createHmac('sha256', secret).update(message).digest('hex');
}
