# Import Server Certificate to System Keychain and Verify

sudo security import server/private/<fqdn>.<hash>.p12 -k /Library/Keychains/System.keychain -P "$(head -1 server/private/passphrase.txt)" -A
security verify-cert -c server/certs/<fqdn>.<hash>.cer
