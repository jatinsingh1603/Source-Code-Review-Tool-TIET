import crypto from 'crypto';
import os from 'os';

export function digest(value) {
  return crypto.createHash('md5').update(value).digest('hex');
}
