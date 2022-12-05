# Generate EC private key:
openssl ecparam -name prime256v1 -genkey -noout -out ec.pem

# Extract/generate the public key from the private key:
openssl ec -in ec.pem -pubout -out ec.pub

# Generate public key in Subject Public-Key Infomation format:
openssl ec -in ec.pem -pubout -outform der -out ec.spki.der

# Generate the key in PKCS8 format:
openssl pkcs8 -in ec.pem -outform der -out ec.pk8.der -topk8 -nocrypt

