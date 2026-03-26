# CryptoLite.lua API Documentation

A comprehensive cryptographic utility library for Lua, built on basexx and OpenSSL capabilities. This library provides encoding/decoding, hashing, signing, encryption/decryption, and JWK (JSON Web Key) operations.

## Table of Contents

1. [Encoding/Decoding Functions](#encodingdecoding-functions)
2. [Utility Functions](#utility-functions)
3. [Key Generation](#key-generation)
4. [Signing and Signature Verification](#signing-and-signature-verification)
5. [Encryption and Decryption](#encryption-and-decryption)
6. [JWK-Related APIs](#jwk-related-apis)
7. [JWE (JSON Web Encryption) APIs](#jwe-json-web-encryption-apis)

---

## Encoding/Decoding Functions

### Base64 Encoding/Decoding

#### `CryptoLite.base64Encode(data)`
Base64 encode a string.

**Parameters:**
- `data` (string): The data to encode

**Returns:**
- `encoded` (string): Base64-encoded string

**Example:**
```lua
local encoded = CryptoLite.base64Encode("Hello World")
```

---

#### `CryptoLite.base64Decode(data)`
Base64 decode a string.

**Parameters:**
- `data` (string): Base64-encoded string

**Returns:**
- `decoded` (string): Decoded string

**Example:**
```lua
local decoded = CryptoLite.base64Decode("SGVsbG8gV29ybGQ=")
```

---

### Base64URL Encoding/Decoding

#### `CryptoLite.base64URLEncode(data)`
Base64URL encode a string (URL-safe base64 encoding used in JWT).

**Parameters:**
- `data` (string): The data to encode

**Returns:**
- `encoded` (string): Base64URL-encoded string

**Example:**
```lua
local encoded = CryptoLite.base64URLEncode("Hello World")
```

---

#### `CryptoLite.base64URLDecode(data)`
Base64URL decode a string (URL-safe base64 decoding used in JWT).

**Parameters:**
- `data` (string): Base64URL-encoded string

**Returns:**
- `decoded` (string): Decoded string

**Example:**
```lua
local decoded = CryptoLite.base64URLDecode("SGVsbG8gV29ybGQ")
```

---

### Byte Array and String Conversions

#### `CryptoLite.BAtoByteString(byteArray)`
Convert a byte array to a byte string representation.

**Parameters:**
- `byteArray` (table): Array of integer byte values

**Returns:**
- `byteString` (string): Byte string of these bytes

**Example:**
```lua
local byteString = CryptoLite.BAtoByteString({72, 101, 108, 108, 111})
```

---

#### `CryptoLite.ByteStringtoBA(byteString)`
Convert a byte string to a byte array representation.

**Parameters:**
- `byteString` (string): Byte string

**Returns:**
- `byteArray` (table): Array of integer byte values

**Example:**
```lua
local byteArray = CryptoLite.ByteStringtoBA("Hello")
```

---

### Hexadecimal Conversions

#### `CryptoLite.BAtohex(byteArray)`
Convert a byte array to a lowercase hex string representation.

**Parameters:**
- `byteArray` (table): Array of integer byte values

**Returns:**
- `hex` (string): Hex string of these bytes

**Example:**
```lua
local hex = CryptoLite.BAtohex({72, 101, 108, 108, 111})
-- Returns: "48656c6c6f"
```

---

#### `CryptoLite.hextoBA(hex)`
Convert a hex string to a byte array.

**Parameters:**
- `hex` (string): Hex string (e.g., "48656c6c6f" for "Hello")

**Returns:**
- `byteArray` (table): Array of integer byte values (e.g., {72, 101, 108, 108, 111})

**Example:**
```lua
local byteArray = CryptoLite.hextoBA("48656c6c6f")
```

---

#### `CryptoLite.ByteStringtohex(byteString)`
Convert a byte string to a lowercase hex string representation.

**Parameters:**
- `byteString` (string): Byte string

**Returns:**
- `hex` (string): Hex string of these bytes

**Example:**
```lua
local hex = CryptoLite.ByteStringtohex("Hello")
```

---

#### `CryptoLite.hextoByteString(hex)`
Convert a hex string to a byte string.

**Parameters:**
- `hex` (string): Hex string

**Returns:**
- `byteString` (string): Byte string of the hex bytes

**Example:**
```lua
local byteString = CryptoLite.hextoByteString("48656c6c6f")
```

---

### UTF-8 Conversions

#### `CryptoLite.utf8toBA(str)`
Convert a UTF-8 string to a byte array.

**Parameters:**
- `str` (string): String to extract UTF-8 bytes from

**Returns:**
- `array` (table): UTF-8 bytes of the string as an array

**Example:**
```lua
local byteArray = CryptoLite.utf8toBA("Hello")
```

---

#### `CryptoLite.BAtoutf8(byteArray)`
Convert a byte array to a UTF-8 string.

**Parameters:**
- `byteArray` (table): Array of UTF-8 bytes

**Returns:**
- `str` (string): String from the UTF-8 bytes

**Example:**
```lua
local str = CryptoLite.BAtoutf8({72, 101, 108, 108, 111})
```

---

## Utility Functions

### Feature Detection

#### `CryptoLite.checkFeatures()`
Check which advanced features are supported by the current luaossl implementation.

**Returns:**
- `result` (table): Table with feature support flags:
  - `hasAADSupport` (boolean): Support for Additional Authenticated Data (AAD)
  - `hasECDeriveSupport` (boolean): Support for ECDH key derivation

**Example:**
```lua
local features = CryptoLite.checkFeatures()
if features.hasAADSupport then
    -- Use AAD features
end
```

---

### Hashing

#### `CryptoLite.sha256(data)`
Hash a string using SHA-256.

**Parameters:**
- `data` (string): The string to hash

**Returns:**
- `hash` (string): Base64URL-encoded hash

**Example:**
```lua
local hash = CryptoLite.sha256("Hello World")
```

---

### Random Number Generation

#### `CryptoLite.randomBytes(length)`
Generate cryptographically secure random bytes.

**Parameters:**
- `length` (number): Number of random bytes to generate

**Returns:**
- `bytes` (string): Random bytes as a string

**Example:**
```lua
local randomData = CryptoLite.randomBytes(32)
```

---

### Key Derivation

#### `CryptoLite.concatKDF(options)`
Implements the Concat KDF algorithm as defined in RFC7518 Section 4.6.2 and NIST SP 800-56A Rev. 3. Used for key derivation in JWE with ECDH-ES key agreement.

**Parameters:**
- `options` (table): Table with the following fields:
  - `sharedSecret` (string, required): The shared secret (Z) from key agreement
  - `keyDataLen` (number, required): The desired output key length in bits
  - `algorithm` (string, required): The algorithm identifier value as a string (e.g., "A256GCM")
  - `apu` (string, optional): Agreement PartyUInfo (base64url encoded)
  - `apv` (string, optional): Agreement PartyVInfo (base64url encoded)

**Returns:**
- `derivedKey` (string): The derived key material

**Example:**
```lua
local key = CryptoLite.concatKDF({
    sharedSecret = sharedSecretBytes,
    keyDataLen = 256,
    algorithm = "A256GCM",
    apu = "base64url_encoded_apu",
    apv = "base64url_encoded_apv"
})
```

---

## Key Generation

### RSA Key Generation

#### `CryptoLite.generateRSAKeyPair(bits)`
Generate an RSA key pair.

**Parameters:**
- `bits` (number, optional): Key size in bits (default: 2048, recommended: 2048 or 4096)

**Returns:**
- `publicKeyPEM` (string): The public key in PEM format
- `privateKeyPEM` (string): The private key in PEM format

**Example:**
```lua
local publicKey, privateKey = CryptoLite.generateRSAKeyPair(2048)
```

---

### ECDSA Key Generation

#### `CryptoLite.generateECDSAKeyPair(curve)`
Generate an ECDSA key pair.

**Parameters:**
- `curve` (string, optional): Curve name (default: "prime256v1")
  - Supported curves: "prime256v1", "secp384r1", "secp521r1"

**Returns:**
- `publicKeyPEM` (string): The public key in PEM format
- `privateKeyPEM` (string): The private key in PEM format

**Example:**
```lua
local publicKey, privateKey = CryptoLite.generateECDSAKeyPair("prime256v1")
```

---

### EC Key Properties

#### `CryptoLite.determineECKeyProperties(pem)`
Get EC curve information from the PEM of either the key (public or private) or the ECParameters.

**Parameters:**
- `pem` (string): PEM of key or ECParameters

**Returns:**
- `curveInfo` (table): Table with curve information:
  - `keyLenBits` (number): Key length in bits
  - `curveName` (string): Curve name

**Example:**
```lua
local curveInfo = CryptoLite.determineECKeyProperties(publicKeyPEM)
print("Curve: " .. curveInfo.curveName)
print("Key length: " .. curveInfo.keyLenBits)
```

---

## Signing and Signature Verification

### Algorithm Support

#### `CryptoLite.isSupportedSignatureAlgorithm(algorithm)`
Check whether the given algorithm identifier is a supported signing algorithm.

**Supported Algorithms:**
- `"none"` - No signature
- `"HS256"`, `"HS384"`, `"HS512"` - HMAC with SHA-256/384/512
- `"RS256"`, `"RS384"`, `"RS512"` - RSA with SHA-256/384/512
- `"ES256"`, `"ES384"`, `"ES512"` - ECDSA with SHA-256/384/512

**Parameters:**
- `algorithm` (string): The signing algorithm identifier string

**Returns:**
- `supported` (boolean): true if the algorithm is supported, false otherwise

**Example:**
```lua
if CryptoLite.isSupportedSignatureAlgorithm("RS256") then
    -- Use RS256 signing
end
```

---

### Digital Signing

#### `CryptoLite.sign(data, key, alg)`
Digitally sign data with a key using the specified algorithm.

**Parameters:**
- `data` (string): Data to sign
- `key` (string): Key to sign with (secret for HMAC, private key PEM for RSA/ECDSA)
- `alg` (string): Name of signature algorithm (e.g., "HS256", "RS256", "ES256")

**Returns:**
- `signature` (string): Base64URL-encoded signature of data using key

**Example:**
```lua
-- HMAC signing
local signature = CryptoLite.sign("Hello World", "secret", "HS256")

-- RSA signing
local signature = CryptoLite.sign("Hello World", privateKeyPEM, "RS256")

-- ECDSA signing
local signature = CryptoLite.sign("Hello World", ecPrivateKeyPEM, "ES256")
```

---

### Signature Verification

#### `CryptoLite.verify(data, signature, key, alg)`
Digitally verify signed data with a key using the specified algorithm.

**Parameters:**
- `data` (string): Data to verify
- `signature` (string): Signature to verify (base64URL-encoded)
- `key` (string): Key to verify with (secret for HMAC, public key PEM for RSA/ECDSA)
- `alg` (string): Name of signature algorithm (same as used in sign)

**Returns:**
- `valid` (boolean): true if signature is valid, false otherwise

**Example:**
```lua
-- HMAC verification
local isValid = CryptoLite.verify("Hello World", signature, "secret", "HS256")

-- RSA verification
local isValid = CryptoLite.verify("Hello World", signature, publicKeyPEM, "RS256")

-- ECDSA verification
local isValid = CryptoLite.verify("Hello World", signature, ecPublicKeyPEM, "ES256")
```

---

## Encryption and Decryption

### Algorithm Support

#### `CryptoLite.isSupportedContentEncryptionAlgorithm(algorithm)`
Check whether the given algorithm identifier is a supported JWE content encryption algorithm.

**Supported Algorithms:**
- `"A128GCM"`, `"A192GCM"`, `"A256GCM"` - AES-GCM modes
- `"A128CBC-HS256"`, `"A192CBC-HS384"`, `"A256CBC-HS512"` - AES-CBC with HMAC-SHA2

**Parameters:**
- `algorithm` (string): The content encryption algorithm identifier string

**Returns:**
- `supported` (boolean): true if the algorithm is supported, false otherwise

**Example:**
```lua
if CryptoLite.isSupportedContentEncryptionAlgorithm("A256GCM") then
    -- Use A256GCM encryption
end
```

---

#### `CryptoLite.isSupportedEncryptionKeyAgreementAlgorithm(algorithm)`
Check whether the given algorithm identifier is a supported JWE key agreement/key encryption algorithm.

**Supported Algorithms:**
- `"RSA-OAEP"` - RSA with OAEP padding
- `"RSA1_5"` - RSA with PKCS#1 v1.5 padding
- `"dir"` - Direct encryption (shared symmetric key)
- `"ECDH-ES"` - Elliptic Curve Diffie-Hellman Ephemeral Static

**Parameters:**
- `algorithm` (string): The key agreement algorithm identifier string

**Returns:**
- `supported` (boolean): true if the algorithm is supported, false otherwise

**Example:**
```lua
if CryptoLite.isSupportedEncryptionKeyAgreementAlgorithm("RSA-OAEP") then
    -- Use RSA-OAEP key agreement
end
```

---

#### `CryptoLite.isECDHEncryptionKeyAgreement(algorithm)`
Determine whether the specified key agreement algorithm uses ECDH (Elliptic Curve Diffie-Hellman).

**Parameters:**
- `algorithm` (string): The key agreement algorithm name

**Returns:**
- `isECDH` (boolean): true if the algorithm is ECDH-based, false otherwise

**Example:**
```lua
if CryptoLite.isECDHEncryptionKeyAgreement("ECDH-ES") then
    -- Handle ECDH-specific logic
end
```

---

### General Encryption/Decryption

#### `CryptoLite.encrypt(options)`
Encrypt plaintext using the specified JWE-compatible key agreement and content encryption algorithms.

**Parameters:**
- `options` (table): Table containing:
  - `plaintext` (string, required): The string to encrypt
  - `key` (string, required): Encryption key (public key PEM for RSA/ECDH, symmetric key for dir)
  - `encryptionKeyAgreement` (string, required): JWE key agreement algorithm (e.g., "RSA-OAEP", "ECDH-ES", "dir")
  - `contentEncryptionAlgorithm` (string, required): JWE content encryption algorithm (e.g., "A256GCM")
  - `iv` (string, optional): Initialization vector bytes
  - `apu` (string, optional): Agreement PartyUInfo (ECDH-ES only)
  - `apv` (string, optional): Agreement PartyVInfo (ECDH-ES only)
  - `ephemeralKey` (pkey, optional): Ephemeral EC key pair (ECDH-ES only)
  - `additionalAuthenticatedData` (string, optional): AAD for AEAD cipher modes

**Returns:**
- For RSA: Table with `iv`, `tag`, `ciphertext`, and `encryptedKey` fields
- For ECDH-ES: Table with `ephemeralKeyPublicPEM`, `iv`, `tag`, `ciphertext`, and `encryptedKey` fields
- For dir: Table with `iv`, `tag`, `ciphertext`, and `salt` fields

**Example:**
```lua
-- RSA encryption
local encrypted = CryptoLite.encrypt({
    plaintext = "Secret message",
    key = publicKeyPEM,
    encryptionKeyAgreement = "RSA-OAEP",
    contentEncryptionAlgorithm = "A256GCM"
})

-- Direct symmetric encryption
local encrypted = CryptoLite.encrypt({
    plaintext = "Secret message",
    key = symmetricKey,
    encryptionKeyAgreement = "dir",
    contentEncryptionAlgorithm = "A256GCM"
})
```

---

#### `CryptoLite.decrypt(options)`
Decrypt ciphertext using the specified JWE-compatible key agreement and content encryption algorithms.

**Parameters:**
- `options` (table): Table containing:
  - `ciphertext` (string, required): The ciphertext to decrypt
  - `key` (string, required): The decryption key or private key in PEM format
  - `encryptionKeyAgreement` (string, required): JWE key agreement algorithm
  - `contentEncryptionAlgorithm` (string, required): JWE content encryption algorithm
  - `iv` (string, optional): IV bytes used during encryption
  - `tag` (string, optional): AEAD authentication tag
  - `ephemeralKeyPublicPEM` (string, optional): Sender's ephemeral EC public key in PEM format (ECDH-ES only)
  - `apu` (string, optional): Agreement PartyUInfo (ECDH-ES only)
  - `apv` (string, optional): Agreement PartyVInfo (ECDH-ES only)
  - `encryptedKey` (string, optional): Wrapped CEK (RSA/ECDH with key wrapping)
  - `salt` (string, optional): PBKDF2 salt used during encryption (dir mode only)
  - `additionalAuthenticatedData` (string, optional): AAD for AEAD cipher modes

**Returns:**
- `plaintext` (string): The decrypted plaintext byte string

**Example:**
```lua
-- RSA decryption
local plaintext = CryptoLite.decrypt({
    ciphertext = encrypted.ciphertext,
    key = privateKeyPEM,
    encryptionKeyAgreement = "RSA-OAEP",
    contentEncryptionAlgorithm = "A256GCM",
    encryptedKey = encrypted.encryptedKey,
    iv = encrypted.iv,
    tag = encrypted.tag
})
```

---

### Simplified Symmetric Encryption

#### `CryptoLite.encryptSymmetric(plaintext, key)`
Symmetric encryption using A256GCM (default). Simplified interface that returns a single base64URL-encoded string.

**Parameters:**
- `plaintext` (string): The string to encrypt
- `key` (string): Encryption key. If less than 32 bytes, will be derived using PBKDF2 with salt

**Returns:**
- `encrypted` (string): Base64URL-encoded encrypted data with format: salt:iv:tag:ciphertext

**Example:**
```lua
local encrypted = CryptoLite.encryptSymmetric("Secret message", "mypassword")
```

---

#### `CryptoLite.decryptSymmetric(encrypted, key)`
Symmetric decryption using A256GCM (default). Decrypts data encrypted with `encryptSymmetric`.

**Parameters:**
- `encrypted` (string): Base64URL-encoded encrypted data from encryptSymmetric
- `key` (string): Decryption key (same as used for encryption)

**Returns:**
- `plaintext` (string): The decrypted string

**Example:**
```lua
local plaintext = CryptoLite.decryptSymmetric(encrypted, "mypassword")
```

---

### Simplified RSA Encryption

#### `CryptoLite.encryptRSA(plaintext, publicKeyPEM)`
RSA encryption with RSA-OAEP key agreement and A256GCM content encryption. Simplified interface that returns a single base64URL-encoded string.

**Parameters:**
- `plaintext` (string): The string to encrypt
- `publicKeyPEM` (string): RSA public key in PEM format

**Returns:**
- `encrypted` (string): Base64URL-encoded encrypted data

**Example:**
```lua
local encrypted = CryptoLite.encryptRSA("Secret message", publicKeyPEM)
```

---

#### `CryptoLite.decryptRSA(encrypted, privateKeyPEM)`
RSA decryption with RSA-OAEP key agreement and A256GCM content encryption. Decrypts data encrypted with `encryptRSA`.

**Parameters:**
- `encrypted` (string): Base64URL-encoded encrypted data from encryptRSA
- `privateKeyPEM` (string): RSA private key in PEM format

**Returns:**
- `plaintext` (string): The decrypted string

**Example:**
```lua
local plaintext = CryptoLite.decryptRSA(encrypted, privateKeyPEM)
```

---

### Raw RSA Encryption

#### `CryptoLite.encryptRSARaw(plaintext, publicKeyPEM, rsaPaddingStr)`
Low-level RSA encryption without envelope or encoding. Performs a single RSA encryption operation.

**Parameters:**
- `plaintext` (string): The plaintext as a binary string
- `publicKeyPEM` (string): RSA public key in PEM format
- `rsaPaddingStr` (string): The RSA padding algorithm to use
  - `"RSA_PKCS1_PADDING"` - PKCS#1 v1.5 padding
  - `"RSA_PKCS1_OAEP_PADDING"` - OAEP padding

**Returns:**
- `ciphertext` (string): The raw RSA-encrypted ciphertext bytes (binary string)

**Example:**
```lua
local ciphertext = CryptoLite.encryptRSARaw("Hello", publicKeyPEM, "RSA_PKCS1_OAEP_PADDING")
```

---

#### `CryptoLite.decryptRSARaw(ciphertext, privateKeyPEM, rsaPaddingStr)`
Low-level RSA decryption without envelope or encoding. Performs a single RSA decryption operation.

**Parameters:**
- `ciphertext` (string): The raw RSA-encrypted ciphertext bytes (binary string)
- `privateKeyPEM` (string): RSA private key in PEM format
- `rsaPaddingStr` (string): The RSA padding algorithm to use (same as used for encryption)

**Returns:**
- `plaintext` (string): The decrypted plaintext as a binary string

**Example:**
```lua
local plaintext = CryptoLite.decryptRSARaw(ciphertext, privateKeyPEM, "RSA_PKCS1_OAEP_PADDING")
```

---

### ECDSA Hybrid Encryption

#### `CryptoLite.encryptECDSA(plaintext, publicKeyPEM)`
ECDSA hybrid encryption using ECDH key exchange + AES-256-GCM. Uses Elliptic Curve Diffie-Hellman for key exchange, then symmetric encryption.

**Note:** Not available until the luaossl in ISVA contains the required ECDH derive support.

**Parameters:**
- `plaintext` (string): The string to encrypt
- `publicKeyPEM` (string): EC public key in PEM format

**Returns:**
- `encrypted` (string): Base64URL-encoded encrypted data with format: ephemeralPubKey:iv:tag:ciphertext

**Example:**
```lua
local encrypted = CryptoLite.encryptECDSA("Secret message", ecPublicKeyPEM)
```

---

#### `CryptoLite.decryptECDSA(encrypted, privateKeyPEM)`
ECDSA hybrid decryption. Decrypts data encrypted with `encryptECDSA`.

**Note:** Not available until the luaossl in ISVA contains the required ECDH derive support.

**Parameters:**
- `encrypted` (string): Base64URL-encoded encrypted data from encryptECDSA
- `privateKeyPEM` (string): EC private key in PEM format

**Returns:**
- `plaintext` (string): The decrypted string

**Example:**
```lua
local plaintext = CryptoLite.decryptECDSA(encrypted, ecPrivateKeyPEM)
```

---

## JWK-Related APIs

### JWK to PEM Conversion

#### `CryptoLite.jwkToPEM(jwk)`
Convert a JSON Web Key (JWK) to PEM format.

**Supported Key Types:**
- RSA public keys (kty="RSA", n, e)
- RSA private keys (kty="RSA", n, e, d, p, q, dp, dq, qi)
- EC public keys (kty="EC", crv, x, y)
- EC private keys (kty="EC", crv, x, y, d)
- X.509 certificates (x5c array) - extracts public key from certificate

**Parameters:**
- `jwk` (table): The JSON web key

**Returns:**
- `PEM` (string): The public or private key in PEM format

**Throws:**
- Error if jwk is invalid or unsupported

**Example:**
```lua
local jwk = {
    kty = "RSA",
    n = "base64url_encoded_modulus",
    e = "AQAB"
}
local pem = CryptoLite.jwkToPEM(jwk)
```

---

### PEM to JWK Conversion

#### `CryptoLite.PEMtoJWK(pem)`
Convert PEM to JWK format.

**Supported Key Types:**
- RSA public keys (BEGIN PUBLIC KEY with RSA algorithm)
- RSA private keys (BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY)
- EC public keys (BEGIN PUBLIC KEY with EC algorithm)
- EC private keys (BEGIN EC PRIVATE KEY or BEGIN PRIVATE KEY)

**Parameters:**
- `pem` (string): The PEM-encoded key (public or private, RSA or EC)

**Returns:**
- `jwk` (table): The JSON web key object

**Throws:**
- Error if PEM format is unsupported or unrecognized

**Example:**
```lua
local jwk = CryptoLite.PEMtoJWK(publicKeyPEM)
print("Key type: " .. jwk.kty)
```

---

### JWK Thumbprint

#### `CryptoLite.generateJWKThumbprint(jwk)`
Generate the JWK thumbprint of a public key per RFC 7638.

**Parameters:**
- `jwk` (table): The JSON web key

**Returns:**
- `thumbprint` (string): The JWK thumbprint

**Example:**
```lua
local thumbprint = CryptoLite.generateJWKThumbprint(jwk)
```

---

## JWE (JSON Web Encryption) APIs

### JWE Generation

#### `CryptoLite.generateJWE(options)`
Generate a JWE (JSON Web Encryption) token.

**Parameters:**
- `options` (table): Table containing:
  - `plaintext` (string, required): The plaintext to encrypt
  - `encryptionAlgorithm` (string, required): JWE key agreement algorithm (e.g., "RSA-OAEP", "ECDH-ES")
  - `encryptionKey` (string, required): Encryption key (public key PEM for RSA/ECDH)
  - `encryptionMethod` (string, required): JWE content encryption algorithm (e.g., "A256GCM")
  - `zip` (boolean, optional): Whether to compress plaintext with DEFLATE before encryption

**Returns:**
- `jwe` (string): The JWE token in compact serialization format (5 base64url parts separated by dots)

**Example:**
```lua
local jwe = CryptoLite.generateJWE({
    plaintext = "Secret message",
    encryptionAlgorithm = "RSA-OAEP",
    encryptionKey = recipientPublicKeyPEM,
    encryptionMethod = "A256GCM",
    zip = true
})
```

---

### JWE Decryption

#### `CryptoLite.decryptJWE(options)`
Decrypt a JWE (JSON Web Encryption) token.

**Parameters:**
- `options` (table): Table containing:
  - `jwe` (string, required): The JWE token to decrypt
  - `encryptionAlgorithm` (string, required): JWE key agreement algorithm (must match the one used for encryption)
  - `decryptionKey` (string, required): Decryption key (private key PEM)
  - `encryptionMethod` (string, required): JWE content encryption algorithm (must match the one used for encryption)

**Returns:**
- `decryptResults` (table): Table containing:
  - `jweHeader` (table): The decoded JWE header
  - `plaintext` (string): The decrypted plaintext

**Example:**
```lua
local result = CryptoLite.decryptJWE({
    jwe = jweString,
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = privateKeyPEM,
    encryptionMethod = "A256GCM"
})
print("Plaintext: " .. result.plaintext)
```

---

## Dependencies

This library requires the following Lua modules:
- `LoggingUtils` - Logging utilities
- `basexx` - Base encoding/decoding
- `openssl.cipher` - Symmetric encryption
- `openssl.rand` - Random number generation
- `openssl.kdf` - Key derivation functions
- `openssl.pkey` - Public key operations
- `openssl.digest` - Hashing functions
- `openssl.hmac` - HMAC operations
- `openssl.x509` - X.509 certificate handling
- `ber` - BER/DER encoding/decoding
- `cjson` - JSON encoding/decoding

---

## Notes

### Feature Support

Some features require an updated version of luaossl:
- **AAD Support**: Additional Authenticated Data for symmetric encrypt/decrypt operations
- **ECDH Derive Support**: ECDH key derivation for ECDH-ES encryption key agreement

Use `CryptoLite.checkFeatures()` to detect support at runtime.

### Algorithm Support Summary

**Signature Algorithms:**
- HMAC: HS256, HS384, HS512
- RSA: RS256, RS384, RS512
- ECDSA: ES256, ES384, ES512
- None: none

**Content Encryption Algorithms:**
- AES-GCM: A128GCM, A192GCM, A256GCM
- AES-CBC-HMAC-SHA2: A128CBC-HS256, A192CBC-HS384, A256CBC-HS512

**Key Agreement Algorithms:**
- RSA: RSA1_5, RSA-OAEP
- ECDH: ECDH-ES
- Direct: dir

**Supported EC Curves:**
- prime256v1 (P-256)
- secp384r1 (P-384)
- secp521r1 (P-521)

---

## License

This library is part of the IBM Security Verify Access (ISVA) ecosystem.