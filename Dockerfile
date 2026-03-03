# Multi-stage Docker build for SMTP server
# Stage 1: Build the application
FROM alpine:3.19 AS builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    sqlite-dev \
    musl-dev \
    curl \
    tar \
    xz

# Install Zig (not available in Alpine repos)
ARG ZIG_VERSION=0.16.0-dev.2565+684032671
RUN curl -fsSL "https://ziglang.org/builds/zig-x86_64-linux-${ZIG_VERSION}.tar.xz" | tar -xJ -C /usr/local && \
    ln -s /usr/local/zig-x86_64-linux-${ZIG_VERSION}/zig /usr/local/bin/zig

# Set working directory
WORKDIR /build

# Copy source code
COPY . .

# Build the application in release mode
RUN zig build -Doptimize=ReleaseSafe

# Stage 2: Create minimal runtime image
FROM alpine:3.19

# Install runtime dependencies only
RUN apk add --no-cache \
    sqlite-libs \
    ca-certificates \
    tzdata

# Create non-root user for running the server
RUN addgroup -g 1000 smtp && \
    adduser -D -u 1000 -G smtp smtp

# Create necessary directories
RUN mkdir -p /var/mail/queue /var/mail/storage /var/log/smtp /etc/smtp && \
    chown -R smtp:smtp /var/mail /var/log/smtp /etc/smtp

# Copy binaries from builder
COPY --from=builder /build/zig-out/bin/smtp-server /usr/local/bin/
COPY --from=builder /build/zig-out/bin/user-cli /usr/local/bin/

# Copy TLS certificates directory (if needed)
RUN mkdir -p /etc/smtp/tls

# Switch to non-root user
USER smtp

# Expose SMTP ports
EXPOSE 2525 8025

# Set environment variables with sensible defaults
ENV SMTP_HOST=0.0.0.0 \
    SMTP_PORT=2525 \
    SMTP_HOSTNAME=mail.example.com \
    SMTP_MAX_CONNECTIONS=100 \
    SMTP_MAX_MESSAGE_SIZE=10485760 \
    SMTP_MAX_RECIPIENTS=100 \
    SMTP_ENABLE_TLS=false \
    SMTP_ENABLE_AUTH=true \
    SMTP_ENABLE_DNSBL=false \
    SMTP_ENABLE_GREYLIST=false \
    SMTP_DB_PATH=/var/mail/users.db

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD nc -z localhost ${SMTP_PORT} || exit 1

# Run the SMTP server
CMD ["/usr/local/bin/smtp-server"]
