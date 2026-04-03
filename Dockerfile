# Build stage
FROM node:20-slim AS builder
WORKDIR /app

COPY package.json package-lock.json* ./
# In production, @pdtf/core would be from npm, not a file reference
RUN npm ci --ignore-scripts 2>/dev/null || npm install

COPY tsconfig.json ./
COPY src/ src/
RUN npx tsc

# Runtime stage
FROM node:20-slim
WORKDIR /app

ENV NODE_ENV=production

COPY --from=builder /app/package.json ./
COPY --from=builder /app/node_modules/ ./node_modules/
COPY --from=builder /app/dist/ ./dist/

EXPOSE 8080

# Cloud Run sets PORT=8080 by default
CMD ["node", "dist/server.js"]
