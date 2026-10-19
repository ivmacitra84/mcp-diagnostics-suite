# MCP Diagnostics Suite - production image
FROM node:22-alpine

WORKDIR /app

COPY . ./

RUN npm install --omit=dev || npm install
RUN npm run build || true
RUN node scripts/provenance.js

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s CMD wget -qO- http://localhost:3000/health || exit 1

CMD ["node", "index.js"]
