# Comptra API + dashboard — runs the same Hono app the tests exercise.
FROM node:22-slim AS base
WORKDIR /app

# install deps (workspaces resolved from the root lockfile)
COPY package.json package-lock.json ./
COPY packages/schema/package.json packages/schema/
COPY packages/core/package.json packages/core/
COPY packages/sdk/package.json packages/sdk/
COPY apps/api/package.json apps/api/
RUN npm ci --omit=dev || npm install --omit=dev

# source
COPY . .

ENV PORT=8787
ENV COMPTRA_DATA=/data
VOLUME ["/data"]
EXPOSE 8787

# tsx runs the TypeScript entry directly (no build step); add `npm run build` for a tsc artifact if preferred
CMD ["npx", "tsx", "apps/api/src/server.ts"]
