// Notary state: enrolled keys, live nonces, enrollment challenges, and the
// notary's own signing key. Held in memory; optionally persisted as a single
// JSON file (created at runtime, never committed).

import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

export class Store {
  constructor(path = null) {
    this.path = path;
    this.data = { notaryKey: null, registry: {}, nonces: {}, challenges: {} };
    if (path) {
      try {
        this.data = { ...this.data, ...JSON.parse(readFileSync(path, 'utf8')) };
      } catch (err) {
        if (err.code !== 'ENOENT') throw err;
      }
    }
  }

  save() {
    if (!this.path) return;
    mkdirSync(dirname(this.path), { recursive: true });
    const tmp = this.path + '.tmp';
    writeFileSync(tmp, JSON.stringify(this.data), { mode: 0o600 });
    renameSync(tmp, this.path);
  }

  gc(now = Date.now()) {
    for (const [k, v] of Object.entries(this.data.nonces)) {
      if (v.exp < now) delete this.data.nonces[k];
    }
    for (const [k, v] of Object.entries(this.data.challenges)) {
      if (v.exp < now) delete this.data.challenges[k];
    }
  }
}
