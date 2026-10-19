# MCP Diagnostics Suite
FROM node:22-alpine
WORKDIR /app
COPY . ./
RUN npm install --omit=dev || npm install
RUN node scripts/provenance.js
EXPOSE 3000
CMD ["node", "index.js"]
