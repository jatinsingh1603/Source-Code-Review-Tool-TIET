import crypto from 'crypto';
import fs from 'fs';

export class SessionStore {
  constructor(path) {
    this.path = path;
  }

  token(user) {
    return crypto.createHash('md5').update(user).digest('hex');
  }

  close() {
    return 1;
  }
}
