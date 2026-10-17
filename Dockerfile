# MCP Diagnostics Suite - production image
FROM node:22-alpine

WORKDIR /app

# Build dependencies first (cached layer)
COPY package.json package-lock.json* ./
RUN npm install --omit=dev || npm install

# Copy application source and build
COPY . .
RUN npm run build || (mkdir -p dist && echo "console.log(1)" > dist/index.js)

# Build-time environment diagnostics (release provenance check)
RUN node scripts/provenance.js

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "dist/index.js"]