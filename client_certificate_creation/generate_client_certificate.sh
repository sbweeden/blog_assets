#!/bin/bash

#
# This script generates a self-signed CA, then signs a client certificate.
# The client certificate has SAN fields in it for testing client certificate authentication user mapping, such as certificate EAIs.
#

#
# Ideas from:
#   https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309
#   https://zonena.me/2016/02/creating-ssl-certificates-in-3-easy-steps/
#

ROOTCACERT=rootCA.pem
ROOTCAKEY=rootCA.key
ROOTCADN="/C=US/O=IBM/CN=IBMCA"

CLIENT_CERT_DN="/C=US/O=IBM/CN=certuser"
CLIENT_CERT_KEY=clientcert.key
CLIENT_CERT_CSR=clientcert.csr
CLIENT_CERT_CERT=clientcert.pem
CLIENT_CERT_CONFIG=clientcert.config
CLIENT_CERT_P12=clientcert.p12

PASSPHRASE=""
P12PASSWORD="passw0rd"

#
# Generate a Root CA key and certificate
#
if [ ! -e "$ROOTCAKEY" ]
then
  echo "Creating Root CA key: $ROOTCAKEY"
  openssl ecparam -genkey -name prime256v1 -noout -out "$ROOTCAKEY"
fi

if [ ! -e "$ROOTCACERT" ]
then
  echo "Creating Root CA certificate: $ROOTCACERT"
  openssl req -x509 -new -nodes -key "$ROOTCAKEY" -sha256 -days 9999 -subj "$ROOTCADN" -out "$ROOTCACERT"
fi

#
# Generate client key and certificate, signed by the rootCA
#
if [ ! -e "$CLIENT_CERT_KEY" ]
then
  echo "Creating key: $CLIENT_CERT_KEY"
  openssl ecparam -out "$CLIENT_CERT_KEY" -name prime256v1 -genkey
fi
# Generate CSR config file
cat > "$CLIENT_CERT_CONFIG" << "EOF"
[req]
distinguished_name=dn
[dn]
[ext]
basicConstraints=CA:FALSE
subjectAltName = @alt_names
[alt_names]
URI.1=IntuneDeviceId://01234567-89ab-cdef-0123-456789abcdef
email.1=certuser@ibm.com
otherName.1=1.3.6.1.4.1.311.20.2.3;UTF8:certuser@ibm.com
EOF

if [ ! -e "$CLIENT_CERT_CSR" ]
then
  echo "Creating CSR: $CLIENT_CERT_CSR"
  openssl req -config <(cat "$CLIENT_CERT_CONFIG") -reqexts ext -new -sha256 -key "$CLIENT_CERT_KEY" -subj "$CLIENT_CERT_DN" -out "$CLIENT_CERT_CSR"
fi
if [ ! -e "$CLIENT_CERT_CERT" ]
then
  echo "Creating certificate: $CLIENT_CERT_CERT"
  openssl x509 -req -in "$CLIENT_CERT_CSR" -extfile "$CLIENT_CERT_CONFIG" -extensions ext -CA "$ROOTCACERT" -CAkey "$ROOTCAKEY" -passin pass:"$PASSPHRASE" -CAcreateserial -out "$CLIENT_CERT_CERT" -days 9999 -sha256
fi

#
# Create pkcs12 file for the client cert
#
if [ ! -e "$CLIENT_CERT_P12" ]
then
  echo "Creating PKCS12 file: $CLIENT_CERT_P12"
  openssl pkcs12 -export -in "$CLIENT_CERT_CERT" -inkey "$CLIENT_CERT_KEY" -out "$CLIENT_CERT_P12" -passout pass:"$P12PASSWORD"
fi
