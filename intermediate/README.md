# Import CA and Intermediate CA into System Keychain

# Import and trust CA
sudo security import root/private/root.p12 -k /Library/Keychains/System.keychain -P "$(head -1 root/private/passphrase.txt)" -A
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root/certs/root.cer

# Import intermerdiate CA
sudo security import intermediate/private/intermediate.p12 -k /Library/Keychains/System.keychain -P "$(head -1 intermediate/private/passphrase.txt)" -A

