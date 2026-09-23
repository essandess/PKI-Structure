# Import Code Signing Certificate to System Keychain and Verify

sudo security import codesign/private/codesign.<hash>.p12 -k /Library/Keychains/System.keychain -P "$(head -1 codesign/private/passphrase.txt)" -A
security verify-cert -c codesign/certs/codesign.<hash>.cer
