// Verifier deployment configuration (plain script, loaded before verify.js).
//
// NOTARY_PUB: the base64url public key of the notary this verifier trusts by
// default — printed by the notary at startup and served at /v1/info. Filling
// it in pre-populates the form; visitors can always override it, and
// verification itself never contacts the notary.
//
// NOTARY_NAME: short human label shown next to the pre-filled key.

window.INKLINE_VERIFIER_CONFIG = {
  NOTARY_PUB: 'BDnq31ChitMD2Ui8k6a2XV7YgBMr96X5LLgK5Gch8Cw1HMrUm_4h4ENBx0cHO8rYXys_Plxlw125dLFPPF5VWW0',
  NOTARY_NAME: 'Inkline notary (https://inkline-notary-production.up.railway.app)',
};
