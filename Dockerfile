FROM node:20-slim

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

EXPOSE 7860

# Start node normally
CMD ["node", "index.js"]
