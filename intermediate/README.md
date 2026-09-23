# Import CA and Intermediate CA into System Keychain

# Import and truse CA
sudo security import ca/private/intermediate.p12 -k /Library/Keychains/System.keychain -P "$(head -1 ca/private/passphrase.txt)" -A
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ca/certs/ca.cer

# import intermerdiate CA
sudo security import intermediate/private/intermediate.p12 -k /Library/Keychains/System.keychain -P "$(head -1 intermediate/private/passphrase.txt)" -A

