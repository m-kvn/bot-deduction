FROM node:24-bookworm-slim AS build
WORKDIR /app/bot-signal
COPY bot-signal/package.json bot-signal/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY bot-signal/ ./
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:24-bookworm-slim
ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=8787 \
    DB_FILE=/data/submissions.db
WORKDIR /app/bot-signal
COPY --from=build /app/bot-signal/package.json ./
COPY --from=build /app/bot-signal/node_modules ./node_modules
COPY --from=build /app/bot-signal/dist ./dist
COPY --from=build /app/bot-signal/data ./data
COPY --from=build /app/bot-signal/examples/form-demo ./examples/form-demo
RUN mkdir -p /data && chown node:node /data
USER node
EXPOSE 8787
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --retries=3 \
  CMD ["node", "-e", "fetch(`http://127.0.0.1:${process.env.PORT}/readyz`).then((r) => process.exit(r.ok ? 0 : 1), () => process.exit(1))"]
STOPSIGNAL SIGTERM
CMD ["node", "examples/form-demo/server.mjs"]
