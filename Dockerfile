# ==========================================
# Stage 1: Xray Downloader
# ==========================================
FROM alpine:3.19 AS xray-fetcher

# Define version and expected hash (Optional security step)
ARG XRAY_VERSION="v26.1.18"
ARG XRAY_URL="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/Xray-linux-64.zip"

WORKDIR /tmp

# Install tools
RUN apk add --no-cache curl unzip && \
    curl -L -o xray.zip "$XRAY_URL" && \
    unzip xray.zip && \
    chmod +x xray

# ==========================================
# Stage 2: Node Builder (Compiles TS & SQLite)
# ==========================================
FROM node:20-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache python3 make g++

COPY package*.json ./

# 1. Install ALL dependencies (including dev)
RUN npm install

COPY . .

# 2. Build the TypeScript code
RUN npm run build

# 3. Prune to only Production dependencies
RUN npm prune --production

# ==========================================
# Stage 3: Production Runner (Tiny & Secure)
# ==========================================
FROM node:20-alpine

WORKDIR /app

# Copy the Xray binary from Stage 1
COPY --from=xray-fetcher /tmp/xray ./xray
COPY --from=xray-fetcher /tmp/geoip.dat ./
COPY --from=xray-fetcher /tmp/geosite.dat ./

# Copy built node_modules and code from Stage 2
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/package.json ./

# Create necessary directories
RUN mkdir -p results tmp

# Set Env to Production
ENV NODE_ENV=production

CMD ["node", "dist/index.js", "bot"]