#!/usr/bin/env bash
# Genera el keystore PKCS12 autofirmado de DESARROLLO y exporta su certificado público.
# Uso: ./scripts/generate-keystore.sh
set -euo pipefail

cd "$(dirname "$0")/.."

KEYSTORE=src/main/resources/keystore/devkeystore.p12
CERT=certs/localhost.crt
ALIAS=securebackend
PASSWORD=${SSL_KEYSTORE_PASSWORD:-changeit}

mkdir -p "$(dirname "$KEYSTORE")" "$(dirname "$CERT")"
rm -f "$KEYSTORE"

keytool -genkeypair \
  -alias "$ALIAS" \
  -keyalg RSA -keysize 2048 \
  -storetype PKCS12 \
  -keystore "$KEYSTORE" \
  -storepass "$PASSWORD" -keypass "$PASSWORD" \
  -validity 825 \
  -dname "CN=localhost, OU=Dev, O=SecureBackend, L=Chihuahua, ST=Chihuahua, C=MX" \
  -ext "SAN=dns:localhost,ip:127.0.0.1,ip:0:0:0:0:0:0:0:1"

keytool -exportcert -rfc \
  -alias "$ALIAS" \
  -keystore "$KEYSTORE" -storepass "$PASSWORD" \
  -file "$CERT"

echo "Keystore: $KEYSTORE"
echo "Certificado público (para curl --cacert): $CERT"
