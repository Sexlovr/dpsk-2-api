FROM node:20-slim

# Install Chromium and Xvfb (Virtual Framebuffer for headful browser bypass)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    chromium \
    xvfb \
    git \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Clone your updated repository
RUN git clone https://github.com/Sexlovr/dpsk-2-api.git .

# Install dependencies
RUN npm install

# Create data directory for SQLite persistence in HuggingFace Spaces
RUN mkdir -p /data
RUN chown -R 1000:1000 /data

# HuggingFace requires images to run as non-root user 1000
RUN chown -R 1000:1000 /app
USER 1000

ENV PORT=7860
ENV DATA_DIR=/data
ENV ADMIN_PASSWORD=admin
ENV JWT_SECRET=""
ENV CONV_TIMEOUT_MINUTES=60
ENV PLAYWRIGHT_BROWSERS_PATH=0
# Tell playwright where chromium is on the image
ENV CHROME_EXECUTABLE_PATH=/usr/bin/chromium

EXPOSE 7860

# Start node wrapped in an Xvfb virtual screen to completely bypass AWS WAF headless checks
CMD ["xvfb-run", "--auto-servernum", "--server-args=-screen 0 1280x800x24", "node", "index.js"]
