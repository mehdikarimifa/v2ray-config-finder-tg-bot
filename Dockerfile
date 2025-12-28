# --- Stage 1: Builder ---
FROM node:20-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

# --- Stage 2: Production Runner ---
FROM node:20-alpine

# Install basic tools
RUN apk add --no-cache curl unzip

WORKDIR /app

# DOWNLOAD XRAY
ARG XRAY_DOWNLOAD_URL="https://github.com/XTLS/Xray-core/releases/download/v25.12.8/Xray-linux-64.zip"
RUN curl -L -o xray.zip "$XRAY_DOWNLOAD_URL" && \
    unzip xray.zip && \
    chmod +x xray && \
    rm xray.zip geoip.dat geosite.dat

# Install Dependencies
COPY package*.json ./
RUN npm install --production

# Copy App Code
COPY --from=builder /app/dist ./dist

# Create directories
RUN mkdir -p results tmp

CMD ["node", "dist/index.js", "bot"]