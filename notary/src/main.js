// Notary entry point.
//
// Configuration (environment variables, no secrets in the repo):
//   DATA_DIR             directory for the state file (default ./data);
//                        mount a persistent volume here in production
//   PORT                 listen port (default 8787; Railway injects it)
//
// The notary signing key is generated on first boot and stored in the state
// file, which lives outside version control. There is a single trust tier
// (enclave-unattested) — see server.js.

import { createNotary, TIER } from './server.js';

import { join } from 'node:path';

const dataDir = process.env.DATA_DIR ?? './data';
const storePath = join(dataDir, 'notary.json');
const port = Number(process.env.PORT ?? 8787);

const { server, notary } = await createNotary({ storePath });

server.listen(port, () => {
  console.log(`inkline notary listening on :${port}`);
  console.log(`  tier        ${TIER} (keys registered as attested: false)`);
  console.log(`  state       ${storePath}`);
  console.log(`  notary kid  ${notary.kid}`);
  console.log(`  notary pub  ${notary.pub}`);
});
