#!/bin/bash
# generates long-lived test CA and certificates for e2e tests (TLS/WSS transports).
# committed to the repository, regenerate only if needed: ./gen_certs.sh
#   ca.pem/ca.key         - test CA
#   sems.pem/sems.key     - SEMS listeners (sip-tls, sip-wss), SAN: 127.0.0.1, localhost, yeti.e2e.invalid
#   gw.pem/gw.key         - test agents servers (gateways, remote servers), SAN: 127.0.0.1, gw.e2e.invalid
#   client.pem/client.key - TLS client certificate of test agents

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"

DAYS=36500

genkey() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }

genkey ca.key
openssl req -x509 -new -key ca.key -sha256 -days $DAYS -subj "/CN=yeti e2e test CA" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem

issue() {
    local name=$1 cn=$2 san=$3 eku=$4
    genkey $name.key
    openssl req -new -key $name.key -subj "/CN=$cn" -out $name.csr
    openssl x509 -req -in $name.csr -CA ca.pem -CAkey ca.key -CAcreateserial -sha256 -days $DAYS -out $name.pem \
        -extfile <(printf "subjectAltName=%s\nextendedKeyUsage=%s\nbasicConstraints=CA:FALSE\n" "$san" "$eku")
    rm $name.csr
}

issue sems yeti.e2e.invalid "IP:127.0.0.1,DNS:localhost,DNS:yeti.e2e.invalid" serverAuth,clientAuth
issue gw gw.e2e.invalid "IP:127.0.0.1,DNS:localhost,DNS:gw.e2e.invalid" serverAuth,clientAuth
issue client client.e2e.invalid "DNS:client.e2e.invalid" clientAuth

rm -f ca.srl
