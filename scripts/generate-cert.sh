#!/bin/bash

# Certificate Generation Script for Mail Server TLS Testing
# Generates self-signed certificates for development/testing only
# DO NOT USE IN PRODUCTION - use proper CA-signed certificates

set -e

CERT_DIR="${CERT_DIR:-./certs}"
CERT_FILE="${CERT_FILE:-$CERT_DIR/cert.pem}"
KEY_FILE="${KEY_FILE:-$CERT_DIR/key.pem}"
DAYS="${DAYS:-365}"
SUBJECT="${SUBJECT:-/CN=localhost/O=Mail Server/C=US}"

echo "=== Mail Server Certificate Generator ==="
echo ""
echo "This script generates self-signed certificates for testing only."
echo "DO NOT USE THESE CERTIFICATES IN PRODUCTION!"
echo ""

# Create certs directory if it doesn't exist
mkdir -p "$CERT_DIR"

# Check if certificates already exist
if [ -f "$CERT_FILE" ] && [ -f "$KEY_FILE" ]; then
    echo "Certificates already exist:"
    echo "  Certificate: $CERT_FILE"
    echo "  Private Key: $KEY_FILE"
    echo ""
    read -p "Do you want to overwrite them? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Aborted. Using existing certificates."
        exit 0
    fi
fi

echo "Generating self-signed certificate..."
echo "  Subject: $SUBJECT"
echo "  Valid for: $DAYS days"
echo "  Certificate: $CERT_FILE"
echo "  Private Key: $KEY_FILE"
echo ""

# Generate self-signed certificate with RSA 4096
openssl req -x509 -newkey rsa:4096 -nodes \
    -keyout "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days "$DAYS" \
    -subj "$SUBJECT" \
    -addext "subjectAltName=DNS:localhost,DNS:*.localhost,IP:127.0.0.1,IP:::1"

echo ""
echo "✓ Certificate generation complete!"
echo ""
echo "Certificate details:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A2 "Subject:"
openssl x509 -in "$CERT_FILE" -noout -text | grep -A1 "Validity"
echo ""
echo "To use these certificates with the mail server:"
echo ""
echo "  export SMTP_ENABLE_TLS=true"
echo "  export SMTP_TLS_CERT=$CERT_FILE"
echo "  export SMTP_TLS_KEY=$KEY_FILE"
echo "  ./zig-out/bin/mail"
echo ""
echo "Or via command line:"
echo ""
echo "  ./zig-out/bin/mail --enable-tls --tls-cert $CERT_FILE --tls-key $KEY_FILE"
echo ""
echo "Test with OpenSSL:"
echo ""
echo "  openssl s_client -connect localhost:2525 -starttls smtp -CAfile $CERT_FILE"
echo ""
