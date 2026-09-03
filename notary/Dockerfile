# Inkline notary. Zero npm dependencies; state is one JSON file.
# Build from the REPOSITORY ROOT (the notary imports ../shared):
#   docker build -f notary/Dockerfile -t inkline-notary .
#   docker run -p 8787:8787 -v inkline-data:/data -e DATA_DIR=/data inkline-notary
#
# Mount a persistent volume and point DATA_DIR at it — it holds the
# enrollment registry and the notary's signing key. Losing it invalidates
# every issued receipt's trust anchor. On Railway: `railway volume add
# --mount-path /data`, `railway variables --set DATA_DIR=/data`, and
# `railway variables --set RAILWAY_DOCKERFILE_PATH=notary/Dockerfile`.

FROM node:20-slim
WORKDIR /app
COPY shared ./shared
COPY notary/src ./notary/src
ENV DATA_DIR=/data
ENV PORT=8787
EXPOSE 8787
# Runs as root: platform-mounted volumes (Railway included) are root-owned,
# and the container does nothing but this one process.
CMD ["node", "notary/src/main.js"]
