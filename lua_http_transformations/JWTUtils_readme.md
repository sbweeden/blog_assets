# JWTUtils.lua API Documentation

A comprehensive JWT (JSON Web Token) utility library for Lua, providing JWT generation, validation, encryption (JWE), and JWKS support. This module builds on CryptoLite.lua to provide high-level JWT operations.

## Table of Contents

1. [Overview](#overview)
2. [JWT Generation](#jwt-generation)
3. [JWT Validation](#jwt-validation)
4. [JWT Decoding](#jwt-decoding)
5. [Encrypted JWT (JWE) Generation](#encrypted-jwt-jwe-generation)
6. [Encrypted JWT (JWE) Validation](#encrypted-jwt-jwe-validation)
7. [Supported Algorithms](#supported-algorithms)
8. [Dependencies](#dependencies)

---

## Overview

JWTUtils provides a complete JWT implementation with the following features:

- **JWT Generation**: Create signed JWTs with custom headers and claims
- **JWT Validation**: Verify JWT signatures and validate claims (exp, nbf)
- **JWT Decoding**: Decode JWTs without validation for inspection
- **JWE Support**: Encrypt and decrypt JWTs using JSON Web Encryption
- **JWKS Support**: Automatic key selection from JSON Web Key Sets
- **Multiple Algorithms**: Support for RS256, ES256, HS256, and unsigned (none)
- **Clock Skew Tolerance**: Configurable tolerance for time-based validations
- **Compression**: Optional DEFLATE compression for JWE payloads

---

## JWT Generation

### `JWTUtils.generate(options)`

Generate a signed JWT token.

**Parameters:**

- `options` (table, required): Configuration table with the following fields:
  - `claims` (table, required): JWT payload claims
  - `algorithm` (string, required): Signature algorithm
    - Supported: `"none"`, `"HS256"`, `"HS384"`, `"HS512"`, `"RS256"`, `"RS384"`, `"RS512"`, `"ES256"`, `"ES384"`, `"ES512"`
  - `key` (string, optional): Signing key
    - Private key PEM for RSA/ECDSA algorithms
    - Secret string for HMAC algorithms
    - Not required for `"none"` algorithm
  - `header` (table, optional): JWT header claims (default: `{alg = algorithm, typ = "JWT"}`)
    - Can include custom fields like `kid` (Key ID)

**Returns:**

- `jwt` (string): Complete JWT string in format `header.payload.signature`
- `error` (string): Error message if generation failed (nil on success)

**Throws:**

- Error if required parameters are missing or invalid

**Example - RS256 Signature:**

```lua
local jwt, err = JWTUtils.generate({
    header = {
        alg = "RS256",
        typ = "JWT",
        kid = "key-1"
    },
    claims = {
        sub = "user123",
        name = "John Doe",
        iat = os.time(),
        exp = os.time() + 3600,
        aud = "https://api.example.com",
        iss = "https://auth.example.com"
    },
    algorithm = "RS256",
    key = privateKeyPEM
})

if jwt then
    print("Generated JWT: " .. jwt)
else
    print("Error: " .. err)
end
```

**Example - HMAC Signature:**

```lua
local jwt = JWTUtils.generate({
    claims = {
        sub = "user456",
        exp = os.time() + 1800
    },
    algorithm = "HS256",
    key = "my-secret-key"
})
```

**Example - Unsigned JWT:**

```lua
local jwt = JWTUtils.generate({
    claims = {
        sub = "user789",
        data = "public information"
    },
    algorithm = "none"
})
```

**Example - ECDSA Signature:**

```lua
local jwt = JWTUtils.generate({
    claims = {
        sub = "user999",
        exp = os.time() + 3600
    },
    algorithm = "ES256",
    key = ecPrivateKeyPEM
})
```

---

## JWT Validation

### `JWTUtils.validate(options)`

Validate a JWT token, verifying its signature and optionally checking expiration and not-before claims.

**Parameters:**

- `options` (table, required): Configuration table with the following fields:
  - `jwt` (string, required): The JWT string to validate
  - `algorithm` (string, required): Expected signature algorithm
    - Must match the `alg` claim in the JWT header
  - `key` (string, optional): Verification key
    - Public key PEM for RSA/ECDSA algorithms
    - Secret string for HMAC algorithms
    - Not used for `"none"` algorithm
    - Not required if `jwks` is provided
  - `jwks` (table, optional): JSON Web Key Set for key lookup
    - Alternative to providing `key` directly
    - Automatically selects key based on `kid` in JWT header
  - `validateExp` (boolean, optional): Whether to validate expiration claim (default: `true`)
    - Checks if current time is before `exp` claim
  - `clockSkew` (number, optional): Clock skew tolerance in seconds (default: `0`)
    - Allows for time differences between systems

**Returns:**

- `result` (table): Validation result containing:
  - `jwtHeader` (table): Decoded JWT header
  - `jwtClaims` (table): Decoded JWT payload claims

**Throws:**

- Error with descriptive message if validation fails:
  - Invalid JWT format
  - Algorithm mismatch
  - Signature verification failure
  - Token expired (`exp` claim)
  - Token not yet valid (`nbf` claim)
  - Missing required parameters

**Example - Validate with Direct Key:**

```lua
local result = JWTUtils.validate({
    jwt = jwtString,
    algorithm = "RS256",
    key = publicKeyPEM,
    validateExp = true,
    clockSkew = 60  -- Allow 60 seconds clock skew
})

print("Subject: " .. result.jwtClaims.sub)
print("Expires: " .. result.jwtClaims.exp)
```

**Example - Validate with JWKS:**

```lua
-- JWKS structure
local jwks = {
    keys = {
        {
            kty = "RSA",
            kid = "key-1",
            use = "sig",
            n = "base64url_encoded_modulus",
            e = "AQAB"
        },
        {
            kty = "RSA",
            kid = "key-2",
            use = "sig",
            n = "base64url_encoded_modulus",
            e = "AQAB"
        }
    }
}

local result = JWTUtils.validate({
    jwt = jwtString,
    algorithm = "RS256",
    jwks = jwks,
    validateExp = true,
    clockSkew = 30
})

print("Token validated successfully")
print("Key ID used: " .. result.jwtHeader.kid)
```

**Example - Validate HMAC JWT:**

```lua
local result = JWTUtils.validate({
    jwt = jwtString,
    algorithm = "HS256",
    key = "my-secret-key",
    validateExp = true
})
```

**Example - Validate Unsigned JWT:**

```lua
local result = JWTUtils.validate({
    jwt = jwtString,
    algorithm = "none",
    validateExp = false
})
```

**Example - Error Handling:**

```lua
local success, result = pcall(JWTUtils.validate, {
    jwt = jwtString,
    algorithm = "RS256",
    key = publicKeyPEM
})

if success then
    print("Valid JWT")
    print("Claims: " .. cjson.encode(result.jwtClaims))
else
    print("Validation failed: " .. result)
end
```

---

## JWT Decoding

### `JWTUtils.decode(jwt)`

Decode a JWT without validation. Useful for inspecting tokens without verifying signatures or checking expiration.

**Warning:** This function does NOT validate the JWT signature or claims. Use only for inspection purposes, not for security-critical operations.

**Parameters:**

- `jwt` (string, required): The JWT string to decode

**Returns:**

- `result` (table): Decoded JWT containing:
  - `jwtHeader` (table): Decoded JWT header
  - `jwtClaims` (table): Decoded JWT payload claims

**Throws:**

- Error if JWT format is invalid or decoding fails

**Example:**

```lua
local result = JWTUtils.decode(jwtString)

print("Algorithm: " .. result.jwtHeader.alg)
print("Subject: " .. result.jwtClaims.sub)
print("Issuer: " .. result.jwtClaims.iss)
print("Expires: " .. result.jwtClaims.exp)

-- Check if token is expired (manual check)
if result.jwtClaims.exp and result.jwtClaims.exp < os.time() then
    print("Warning: Token is expired")
end
```

**Example - Inspect Token Structure:**

```lua
local result = JWTUtils.decode(jwtString)

print("Header:")
for k, v in pairs(result.jwtHeader) do
    print("  " .. k .. ": " .. tostring(v))
end

print("\nClaims:")
for k, v in pairs(result.jwtClaims) do
    print("  " .. k .. ": " .. tostring(v))
end
```

---

## Encrypted JWT (JWE) Generation

### `JWTUtils.generateEncrypted(options)`

Generate an encrypted JWT (JWE) using the signed-then-encrypted pattern. This function creates a signed JWT and then encrypts it using JSON Web Encryption.

**Parameters:**

- `options` (table, required): Configuration table with the following fields:
  
  **For Encryption (Required):**
  - `encryptionAlgorithm` (string, required): JWE key agreement algorithm
    - `"RSA-OAEP"` - RSA with OAEP padding
    - `"RSA1_5"` - RSA with PKCS#1 v1.5 padding
    - `"ECDH-ES"` - Elliptic Curve Diffie-Hellman (requires updated luaossl)
  - `encryptionKey` (string, required): Encryption key
    - Public key PEM for RSA/ECDH algorithms
    - Shared secret for `"dir"` algorithm (not yet supported)
  - `encryptionMethod` (string, required): Content encryption algorithm
    - `"A128GCM"`, `"A192GCM"`, `"A256GCM"` - AES-GCM modes
    - `"A128CBC-HS256"`, `"A192CBC-HS384"`, `"A256CBC-HS512"` - AES-CBC with HMAC
  
  **For JWT Generation (Optional - provide either `jwt` OR these fields):**
  - `jwt` (string, optional): Pre-signed JWT to encrypt
    - If provided, the following fields are not needed
  - `claims` (table, optional): JWT payload claims (required if `jwt` not provided)
  - `signatureAlgorithm` (string, optional): Signature algorithm (required if `jwt` not provided)
  - `signatureKey` (string, optional): Signing key (required if `jwt` not provided)
  - `header` (table, optional): JWT header for generation
  
  **Additional Options:**
  - `kid` (string, optional): Key ID for JWE header
  - `apu` (string, optional): Agreement PartyUInfo for JWE header
  - `apv` (string, optional): Agreement PartyVInfo for JWE header
  - `zip` (boolean, optional): Enable DEFLATE compression before encryption (default: `false`)

**Returns:**

- `jwe` (string): Encrypted JWT in JWE compact serialization format
  - Format: `header.encryptedKey.iv.ciphertext.tag` (5 base64url parts)

**Throws:**

- Error if required parameters are missing or invalid
- Error if encryption or signing fails

**Example - RSA-OAEP Encryption:**

```lua
local jwe = JWTUtils.generateEncrypted({
    claims = {
        sub = "user123",
        exp = os.time() + 3600,
        data = "sensitive information"
    },
    signatureAlgorithm = "RS256",
    signatureKey = signingPrivateKeyPEM,
    encryptionAlgorithm = "RSA-OAEP",
    encryptionKey = recipientPublicKeyPEM,
    encryptionMethod = "A256GCM",
    kid = "recipient-key-1"
})

print("Encrypted JWT: " .. jwe)
```

**Example - With Compression:**

```lua
local jwe = JWTUtils.generateEncrypted({
    claims = {
        sub = "user456",
        exp = os.time() + 3600,
        largeData = string.rep("x", 10000)  -- Large payload
    },
    signatureAlgorithm = "RS256",
    signatureKey = privateKeyPEM,
    encryptionAlgorithm = "RSA-OAEP",
    encryptionKey = recipientPublicKeyPEM,
    encryptionMethod = "A256GCM",
    zip = true  -- Enable compression
})
```

**Example - Encrypt Pre-signed JWT:**

```lua
-- First, generate a signed JWT
local jwt = JWTUtils.generate({
    claims = {sub = "user789", exp = os.time() + 3600},
    algorithm = "RS256",
    key = privateKeyPEM
})

-- Then encrypt it
local jwe = JWTUtils.generateEncrypted({
    jwt = jwt,
    encryptionAlgorithm = "RSA-OAEP",
    encryptionKey = recipientPublicKeyPEM,
    encryptionMethod = "A256GCM"
})
```

**Example - ECDH-ES Encryption:**

```lua
-- Requires updated luaossl with ECDH derive support
local jwe = JWTUtils.generateEncrypted({
    claims = {
        sub = "user999",
        exp = os.time() + 3600
    },
    signatureAlgorithm = "ES256",
    signatureKey = ecSigningPrivateKeyPEM,
    encryptionAlgorithm = "ECDH-ES",
    encryptionKey = recipientECPublicKeyPEM,
    encryptionMethod = "A256GCM",
    apu = "sender-info",
    apv = "recipient-info"
})
```

---

## Encrypted JWT (JWE) Validation

### `JWTUtils.validateEncrypted(options)`

Validate an encrypted JWT (JWE) using the decrypt-then-verify pattern. This function decrypts the JWE and then validates the inner signed JWT.

**Parameters:**

- `options` (table, required): Configuration table with the following fields:
  
  **For Decryption (Required):**
  - `jwe` (string, required): The JWE string to decrypt and validate
  - `encryptionAlgorithm` (string, required): Expected encryption algorithm
    - Must match the `alg` claim in the JWE header
    - `"RSA-OAEP"`, `"RSA1_5"`, `"ECDH-ES"`
  - `decryptionKey` (string, required): Decryption key
    - Private key PEM for RSA/ECDH algorithms
    - Shared secret for `"dir"` algorithm (not yet supported)
  - `encryptionMethod` (string, required): Expected content encryption algorithm
    - Must match the `enc` claim in the JWE header
  
  **For JWT Validation (Required):**
  - `signatureAlgorithm` (string, required): Expected signature algorithm for inner JWT
  - `signatureKey` (string, optional): Public key PEM or secret for signature verification
    - Not required if `jwks` is provided
  - `jwks` (table, optional): JWKS for signature verification
    - Alternative to providing `signatureKey` directly
  
  **Additional Options:**
  - `validateExp` (boolean, optional): Whether to validate expiration (default: `true`)
  - `clockSkew` (number, optional): Clock skew tolerance in seconds (default: `0`)

**Returns:**

- `result` (table): Validation result containing:
  - `jweHeader` (table): Decoded JWE header
  - `jwtHeader` (table): Decoded JWT header (from inner JWT)
  - `jwtClaims` (table): Decoded JWT payload claims (from inner JWT)

**Throws:**

- Error with descriptive message if validation fails:
  - Invalid JWE format
  - Decryption failure
  - Algorithm mismatch
  - Signature verification failure
  - Token expired or not yet valid

**Example - RSA-OAEP Decryption:**

```lua
local result = JWTUtils.validateEncrypted({
    jwe = jweString,
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = recipientPrivateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    signatureKey = signerPublicKeyPEM,
    validateExp = true,
    clockSkew = 60
})

print("Subject: " .. result.jwtClaims.sub)
print("JWE Algorithm: " .. result.jweHeader.alg)
print("JWT Algorithm: " .. result.jwtHeader.alg)
```

**Example - With JWKS:**

```lua
local jwks = {
    keys = {
        {
            kty = "RSA",
            kid = "signing-key-1",
            n = "base64url_encoded_modulus",
            e = "AQAB"
        }
    }
}

local result = JWTUtils.validateEncrypted({
    jwe = jweString,
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = recipientPrivateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    jwks = jwks,
    validateExp = true
})
```

**Example - ECDH-ES Decryption:**

```lua
-- Requires updated luaossl with ECDH derive support
local result = JWTUtils.validateEncrypted({
    jwe = jweString,
    encryptionAlgorithm = "ECDH-ES",
    decryptionKey = recipientECPrivateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "ES256",
    signatureKey = signerECPublicKeyPEM,
    validateExp = true
})
```

**Example - Error Handling:**

```lua
local success, result = pcall(JWTUtils.validateEncrypted, {
    jwe = jweString,
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = privateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    signatureKey = publicKeyPEM
})

if success then
    print("Valid encrypted JWT")
    print("Claims: " .. cjson.encode(result.jwtClaims))
else
    print("Validation failed: " .. result)
end
```

---

## Supported Algorithms

### Signature Algorithms

The following signature algorithms are supported for JWT generation and validation:

| Algorithm | Type | Description |
|-----------|------|-------------|
| `none` | Unsigned | No signature (use with caution) |
| `HS256` | HMAC | HMAC with SHA-256 |
| `HS384` | HMAC | HMAC with SHA-384 |
| `HS512` | HMAC | HMAC with SHA-512 |
| `RS256` | RSA | RSA with SHA-256 |
| `RS384` | RSA | RSA with SHA-384 |
| `RS512` | RSA | RSA with SHA-512 |
| `ES256` | ECDSA | ECDSA with SHA-256 (P-256 curve) |
| `ES384` | ECDSA | ECDSA with SHA-384 (P-384 curve) |
| `ES512` | ECDSA | ECDSA with SHA-512 (P-521 curve) |

### Encryption Key Agreement Algorithms

The following key agreement algorithms are supported for JWE:

| Algorithm | Type | Description |
|-----------|------|-------------|
| `RSA1_5` | RSA | RSA with PKCS#1 v1.5 padding |
| `RSA-OAEP` | RSA | RSA with OAEP padding (recommended) |
| `ECDH-ES` | ECDH | Elliptic Curve Diffie-Hellman* |
| `dir` | Direct | Direct encryption with shared secret** |

\* Requires updated luaossl with ECDH derive support  
\** Not yet fully supported

### Content Encryption Algorithms

The following content encryption algorithms are supported for JWE:

| Algorithm | Type | Description |
|-----------|------|-------------|
| `A128GCM` | AES-GCM | AES-128 in GCM mode |
| `A192GCM` | AES-GCM | AES-192 in GCM mode |
| `A256GCM` | AES-GCM | AES-256 in GCM mode (recommended) |
| `A128CBC-HS256` | AES-CBC | AES-128-CBC with HMAC-SHA-256 |
| `A192CBC-HS384` | AES-CBC | AES-192-CBC with HMAC-SHA-384 |
| `A256CBC-HS512` | AES-CBC | AES-256-CBC with HMAC-SHA-512 |

---

## Dependencies

This library requires the following Lua modules:

- **CryptoLite.lua** - Cryptographic operations (signing, encryption, key conversion)
- **LoggingUtils** - Logging utilities
- **cjson** - JSON encoding/decoding
- **openssl.pkey** - Public key operations
- **LibDeflate** - DEFLATE compression/decompression for JWE

---

## Common Use Cases

### Use Case 1: API Authentication

```lua
-- Server generates JWT for authenticated user
local jwt = JWTUtils.generate({
    claims = {
        sub = userId,
        iss = "https://auth.example.com",
        aud = "https://api.example.com",
        iat = os.time(),
        exp = os.time() + 3600,
        scope = "read write"
    },
    algorithm = "RS256",
    key = serverPrivateKey
})

-- Client validates JWT on each API request
local result = JWTUtils.validate({
    jwt = jwt,
    algorithm = "RS256",
    key = serverPublicKey,
    validateExp = true
})

if result.jwtClaims.scope:match("read") then
    -- Allow read access
end
```

### Use Case 2: Secure Token Exchange

```lua
-- Service A encrypts JWT for Service B
local jwe = JWTUtils.generateEncrypted({
    claims = {
        sub = "user123",
        data = "sensitive information",
        exp = os.time() + 300
    },
    signatureAlgorithm = "RS256",
    signatureKey = serviceAPrivateKey,
    encryptionAlgorithm = "RSA-OAEP",
    encryptionKey = serviceBPublicKey,
    encryptionMethod = "A256GCM"
})

-- Service B decrypts and validates
local result = JWTUtils.validateEncrypted({
    jwe = jwe,
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = serviceBPrivateKey,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    signatureKey = serviceAPublicKey
})
```

### Use Case 3: JWKS-based Validation

```lua
-- Fetch JWKS from identity provider
local jwks = fetchJWKS("https://auth.example.com/.well-known/jwks.json")

-- Validate JWT using JWKS
local result = JWTUtils.validate({
    jwt = jwtFromClient,
    algorithm = "RS256",
    jwks = jwks,
    validateExp = true,
    clockSkew = 60
})

print("Authenticated user: " .. result.jwtClaims.sub)
```

---

## Security Considerations

1. **Algorithm Selection**:
   - Use `RS256` or `ES256` for asymmetric signatures
   - Use `HS256` only when both parties can securely share a secret
   - Avoid `none` algorithm in production

2. **Key Management**:
   - Keep private keys secure and never expose them
   - Rotate keys regularly
   - Use strong key sizes (RSA 2048+ bits, EC P-256+ curves)

3. **Token Expiration**:
   - Always set `exp` claim with reasonable expiration time
   - Enable `validateExp` in production
   - Use `clockSkew` to handle time synchronization issues

4. **JWE Usage**:
   - Use JWE when transmitting sensitive data in tokens
   - Prefer `RSA-OAEP` over `RSA1_5` for better security
   - Use `A256GCM` for content encryption

5. **Validation**:
   - Always validate JWTs before trusting their contents
   - Verify the `iss` (issuer) and `aud` (audience) claims
   - Check `nbf` (not before) if present

---

## Error Handling

All functions throw errors with descriptive messages when validation or processing fails. Use `pcall` for error handling:

```lua
local success, result = pcall(JWTUtils.validate, {
    jwt = jwtString,
    algorithm = "RS256",
    key = publicKeyPEM
})

if success then
    -- Process valid JWT
    processUser(result.jwtClaims.sub)
else
    -- Handle error
    logError("JWT validation failed: " .. result)
    return 401, "Unauthorized"
end
```

---

## License

This library is part of the IBM Security Verify Access (ISVA) ecosystem.

---

## Notes

- JWE with ECDH-ES requires an updated version of luaossl with ECDH derive support
- Direct encryption (`dir` algorithm) is not yet fully supported
- The library follows JWT/JWE specifications from RFC 7519, RFC 7516, and RFC 7518
- Compression using DEFLATE (`zip = true`) can significantly reduce JWE size for large payloads