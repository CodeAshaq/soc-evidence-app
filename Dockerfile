FROM node:22-slim

WORKDIR /app

# Dependensi dulu agar layer ini ter-cache selama package.json tidak berubah
COPY package*.json ./
RUN npm install --omit=dev --no-audit --no-fund

COPY server ./server
COPY public ./public
COPY docs ./docs
COPY rules.json ./rules.json

# Folder data (triage.json) harus bisa ditulis oleh user non-root
RUN mkdir -p /app/data && chown -R node:node /app/data

ENV NODE_ENV=production \
    HOST=0.0.0.0 \
    PORT=3000

USER node
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server/index.js"]
