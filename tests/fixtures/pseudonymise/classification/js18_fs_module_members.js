import fs from 'fs';

export function save(path, data) {
  return fs.writeFileSync(path, data);
}
