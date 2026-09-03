import { defineRailway, preserve, project, service, volume } from "railway/iac";

export default defineRailway(() => {
  const inklineNotaryVolume = volume("inkline-notary-volume", { alerts: { usage: { "100": {}, "80": {}, "95": {} } }, allowOnlineResize: true, region: "sfo", sizeMB: 500 });
  const inklineNotary = service("inkline-notary", {
    replicas: { "sfo": 1 },
    volumeMounts: { "/data": inklineNotaryVolume },
    env: { DATA_DIR: preserve(), RAILWAY_DOCKERFILE_PATH: preserve() },
    healthcheckPath: "/v1/info",
    healthcheckTimeout: 60,
    restartPolicy: { type: "ON_FAILURE", maxRetries: 10 },
  });

  return project("inkline-notary", {
    resources: [inklineNotary, inklineNotaryVolume],
  });
});
