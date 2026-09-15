// Notary entry point.
//
// Configuration (environment variables, no secrets in the repo):
//   DATA_DIR             directory for the state file (default ./data);
//                        mount a persistent volume here in production
//   PORT                 listen port (default 8787; Railway injects it)
//
// The notary signing key is generated on first boot and stored in the state
// file, which lives outside version control. One trust tier, mandatory:
// enclave-attested via Apple App Attest (macOS 27+) — see server.js.

import { createNotary, TIER_ATTESTED } from './server.js';
import { APPLE_APP_ATTEST_ROOT_PEM } from './apple-root.js';

import { join } from 'node:path';

// "TEAMID.bundle.id" of the signed helper; the attested tier verifies the
// App Attest rpIdHash against it.
const appId = process.env.INKLINE_APP_ID ?? '3N74PKJ4AX.com.inkline.presence-helper';
const dataDir = process.env.DATA_DIR ?? './data';
const storePath = join(dataDir, 'notary.json');
const port = Number(process.env.PORT ?? 8787);

const { server, notary } = await createNotary({ storePath, appId, rootPem: APPLE_APP_ATTEST_ROOT_PEM });

server.listen(port, () => {
  console.log(`inkline notary listening on :${port}`);
  console.log(`  tier        ${TIER_ATTESTED} (App Attest required, both Apple environments)`);
  console.log(`  appId       ${appId}`);
  console.log(`  state       ${storePath}`);
  console.log(`  notary kid  ${notary.kid}`);
  console.log(`  notary pub  ${notary.pub}`);
});
