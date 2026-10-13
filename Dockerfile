# syntax=docker/dockerfile:1
# One Dockerfile, two images:
#   --target app  Node.js runtime for backend, ingest and worker (same image, different command)
#   --target web  Caddy: serves the built UI and terminates HTTPS in front of the API
ARG NODE_IMAGE=node:22-bookworm-slim

# ---- dependencies (cached until a package.json or the lockfile changes) ---------------------
FROM ${NODE_IMAGE} AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY backend/package.json backend/
COPY ingest/package.json ingest/
COPY worker/package.json worker/
COPY frontend/package.json frontend/
RUN npm ci --no-audit --no-fund

# ---- compile TypeScript services and build the UI -------------------------------------------
FROM deps AS build
COPY tsconfig.base.json tsconfig.json ./
COPY packages/core packages/core
COPY backend backend
COPY ingest ingest
COPY worker worker
RUN npx tsc -b
COPY frontend frontend
RUN npm run build -w frontend

# ---- runtime for the Node services (production dependencies only, non-root) -----------------
FROM ${NODE_IMAGE} AS app
ENV NODE_ENV=production
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/core/package.json packages/core/
COPY backend/package.json backend/
COPY ingest/package.json ingest/
COPY worker/package.json worker/
COPY frontend/package.json frontend/
RUN npm ci --omit=dev --no-audit --no-fund \
      -w @logs/core -w @logs/backend -w @logs/ingest -w @logs/worker \
    && npm cache clean --force
COPY --from=build /app/packages/core/dist packages/core/dist
COPY --from=build /app/backend/dist backend/dist
COPY --from=build /app/ingest/dist ingest/dist
COPY --from=build /app/worker/dist worker/dist
COPY backend/migrations backend/migrations
RUN mkdir -p /data/inbox && chown -R node:node /data
USER node
EXPOSE 3000 5514/udp 5514/tcp
CMD ["node", "backend/dist/index.js"]

# ---- edge: static UI + TLS + reverse proxy ----------------------------------------------------
FROM caddy:2.10-alpine AS web
COPY deploy/Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/frontend/dist /srv
