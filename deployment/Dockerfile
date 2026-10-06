# Kasbah API server — production image.
# Build:  docker build -f deployment/Dockerfile -t kasbah-api:9.1.0 .
# Run:    docker run -p 8788:8788 -e KASBAH_PROOF_KEY=<secret> kasbah-api:9.1.0
FROM node:22-slim AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY packages/api-server/package.json packages/api-server/
RUN npm ci --omit=dev --no-audit --no-fund

FROM node:22-slim
ENV NODE_ENV=production
ENV PORT=8788
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./
COPY packages/api-server/ packages/api-server/
COPY src/ src/
COPY .kasbahpolicy.json ./
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:8788/v1/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["node", "packages/api-server/server.js"]
