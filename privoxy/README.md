#!/usr/bin/env sh

: <<'PRIVOXY_PKI_STRUCTURE'
# Privoxy PKI Structure and Installation

These commands installs the `privoxy` PKI structure in the System
Keychain and necessary MacPorts installation directories.

```sh
# Install and trust privoxy certificates into System Keychain

sudo security import privoxy/private/privoxy.p12 -k /Library/Keychains/System.keychain -P "$(head -1 privoxy/private/passphrase.txt)" -A
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain privoxy/certs/privoxy.cer

# Install the PKI
sudo install -o privoxy -g privoxy -m 0644 privoxy/certs/privoxy.cer privoxy/certs/privoxy.cert.pem /opt/local/etc/privoxy/CA
sudo install -o privoxy -g privoxy -m 0640 privoxy/private/privoxy.key.pem privoxy/private/privoxy.p12 privoxy/private/passphrase.txt /opt/local/etc/privoxy/CA
sudo install -o privoxy -g privoxy -m 0644 privoxy/adblock2privoxy/certs/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.cert.pem /opt/local/etc/adblock2privoxy/certs/adblock2privoxy-nginx.cert.pem
sudo install -o privoxy -g privoxy -m 0644 privoxy/adblock2privoxy/certs/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.chain.pem /opt/local/etc/adblock2privoxy/certs/adblock2privoxy-nginx.chain.pem
sudo install -o privoxy -g privoxy -m 0640 privoxy/adblock2privoxy/private/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.key.pem /opt/local/etc/adblock2privoxy/certs/adblock2privoxy-nginx.key.pem
sudo install -o privoxy -g privoxy -m 0640 privoxy/adblock2privoxy/private/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.key.pem.decrypted /opt/local/etc/adblock2privoxy/certs/adblock2privoxy-nginx.key.pem.decrypted
sudo install -o privoxy -g privoxy -m 0640 privoxy/adblock2privoxy/private/passphrase.txt /opt/local/etc/adblock2privoxy/certs/
```

To run this file (all commands currently commented out):
```sh
sh README.md
```
PRIVOXY_PKI_STRUCTURE

# Privoxy PKI Structure

# Install and trust privoxy certificates into System Keychain

# sudo security import privoxy/private/privoxy.p12 -k /Library/Keychains/System.keychain -P "$(head -1 privoxy/private/passphrase.txt)" -A
# sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain privoxy/certs/privoxy.cer

# Install the PKI
# sudo install -o privoxy -g privoxy -m 0644 privoxy/certs/privoxy.cer privoxy/certs/privoxy.cert.pem /opt/local/etc/privoxy/CA
# sudo install -o privoxy -g privoxy -m 0640 privoxy/private/privoxy.key.pem privoxy/private/privoxy.p12 /opt/local/etc/privoxy/CA
# sudo install -o privoxy -g privoxy -m 0644 privoxy/adblock2privoxy/certs/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.cert.pem privoxy/adblock2privoxy/certs/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.chain.pem /opt/local/etc/adblock2privoxy/certs
# sudo install -o privoxy -g privoxy -m 0640 privoxy/adblock2privoxy/private/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.key.pem privoxy/adblock2privoxy/private/adblock2privoxy-nginx.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.key.pem.decrypted privoxy/adblock2privoxy/private/passphrase.txt /opt/local/etc/adblock2privoxy/certs
