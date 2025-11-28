# Use a lightweight Node.js image
FROM node:18-alpine

# Install basic tools needed for downloading Xray
RUN apk add --no-cache curl unzip

# Set working directory
WORKDIR /app

# Copy package files and install dependencies first (for caching)
COPY package*.json ./
RUN npm install --production

# --- DOWNLOAD XRAY CORE ---
ENV XRAY_VERSION=1.8.4
RUN curl -L -o xray.zip "https://github.com/XTLS/Xray-core/releases/download/v${XRAY_VERSION}/Xray-linux-64.zip" && \
    unzip xray.zip && \
    chmod +x xray && \
    rm xray.zip geoip.dat geosite.dat

# Copy the rest of your application code
COPY . .

# Create the results directory inside the container to avoid permission issues
RUN mkdir -p results
