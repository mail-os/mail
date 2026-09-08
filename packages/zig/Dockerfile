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

# Install the same Zig 0.17 development snapshot used by local builds and CI.
# No bun needed: the webmail package lives outside this build context, so
# zig build skips the frontend step and uses the committed dist.
#
# Fetched from Pantry's mirror rather than ziglang.org/builds, which garbage
# collects master dev builds: a pin there stops existing after a few weeks and
# every image build 404s on it. Nothing in this Dockerfile runs before the
# toolchain installs, so that failure is total. Pantry mirrors dev builds and
# keeps them, and ships a statically linked zig, so it runs on musl unchanged.
#
# ZIG_VERSION must stay identical to the ziglang.org pin in the repo's
# pantry.jsonc — the Docker context is packages/zig only, so this file cannot
# read it and CI asserts the two match instead. ZIG_SHA256 is the sha256 of the
# mirror's tarball and changes with it.
ARG ZIG_VERSION=0.17.0-dev.2033_af24fd11a
ARG ZIG_SHA256=434a18cb106f4e1c94d6c174488cd9766f7af84db9b1b3a1866b98822bcfefac
RUN curl -fsSL -o /tmp/zig.tar.gz "https://registry.pantry.dev/binaries/ziglang.org/${ZIG_VERSION}/linux-x86-64/ziglang.org-${ZIG_VERSION}.tar.gz" && \
    echo "${ZIG_SHA256}  /tmp/zig.tar.gz" | sha256sum -c - && \
    mkdir -p /usr/local/zig && \
    tar -xzf /tmp/zig.tar.gz -C /usr/local/zig && rm /tmp/zig.tar.gz && \
    ln -s /usr/local/zig/bin/zig /usr/local/bin/zig

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

# Copy binary from builder
COPY --from=builder /build/zig-out/bin/mail /usr/local/bin/

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

# Run the mail server
CMD ["/usr/local/bin/mail", "serve"]
