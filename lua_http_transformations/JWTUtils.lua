--[[
    JWTUtils.lua - JWT Generation and Validation Module
    
    This module provides comprehensive JWT (JSON Web Token) functionality including:
    - JWT generation with custom headers and claims
    - JWT validation with signature verification
    - Support for unsigned JWTs (alg: "none")
    - Support for RS256, ES256, and HS256 algorithms
    - JWKS (JSON Web Key Set) support for key management
    - Automatic expiration (exp) validation
    - Flexible key selection from JWKS
    
    Dependencies:
    - CryptoLite.lua (for cryptographic operations)
    - cjson (for JSON encoding/decoding)
    
    Usage Examples:
    
    -- Generate JWT with RS256
    local jwt = JWTUtils.generate({
        header = {alg = "RS256", typ = "JWT"},
        claims = {sub = "user123", exp = os.time() + 3600},
        algorithm = "RS256",
        key = privateKeyPEM
    })
    
    -- Validate JWT with JWKS
    local valid, header, claims, err = JWTUtils.validate({
        jwt = jwtString,
        algorithm = "RS256",
        jwks = jwksData,
        validateExp = true
    })
--]]

local JWTUtils = {}

-- Load required modules
local logger = require 'LoggingUtils'
local cryptoLite = require "CryptoLite"
local cjson = require "cjson"
local pkey = require "openssl.pkey"
local libDeflate = require("LibDeflate")

--[[
    ============================================================================
    HELPER FUNCTIONS
    ============================================================================
--]]

--[[
    Find a key in JWKS by key ID (kid)
    @param jwks: JWKS data structure
    @param kid: Key ID to find
    @return key: The matching key object or nil
--]]
local function findKeyInJWKS(jwks, kid)
    if not jwks or not jwks.keys then
        return nil
    end
    
    for _, key in ipairs(jwks.keys) do
        if key.kid == kid then
            return key
        end
    end
    
    return nil
end

--[[
    Convert JWK to PEM format
    @param jwk: JSON Web Key object
    @return pem: PEM-formatted key string or nil
--]]
local function jwkToPEM(jwk)
    -- For x5c (X.509 certificate chain), use the first certificate
    if jwk.x5c and #jwk.x5c > 0 then
        local cert = jwk.x5c[1]
        return "-----BEGIN CERTIFICATE-----\n" .. cert .. "\n-----END CERTIFICATE-----"
    end
    
    -- For direct key material (n, e for RSA or x, y for EC)
    -- This is a simplified implementation - full JWK to PEM conversion
    -- would require more complex ASN.1 encoding
    -- For production use, consider using pre-converted PEM keys in JWKS
    
    return nil
end

--[[
    Get all potential verification keys from JWKS
    @param jwks: JWKS data structure
    @param kid: Optional key ID to filter by
    @param alg: Optional algorithm to filter by
    @return keys: Array of PEM-formatted keys
--]]
local function getVerificationKeysFromJWKS(jwks, kid, alg)
    local keys = {}
    
    if not jwks or not jwks.keys then
        return keys
    end
    
    for _, jwk in ipairs(jwks.keys) do
        -- Filter by kid if provided
        if kid and jwk.kid ~= kid then
            goto continue
        end
        
        -- Filter by algorithm if provided
        if alg and jwk.alg and jwk.alg ~= alg then
            goto continue
        end
        
        -- Convert JWK to PEM
        local pem = jwkToPEM(jwk)
        if pem then
            table.insert(keys, {pem = pem, kid = jwk.kid, alg = jwk.alg})
        end
        
        ::continue::
    end
    
    return keys
end

local function trimb64u(s)
    -- return a new string which is s with any leading or trailing characters that are
    -- not part of the base64url alphabet removed
    -- base64url alphabet: A-Z, a-z, 0-9, -, _
    -- also preserve . (dot) as it is used as the JWT part separator
    -- strip leading non-b64u characters
    s = s:gsub("^[^A-Za-z0-9%-%_.]+", "")
    -- strip trailing non-b64u characters
    s = s:gsub("[^A-Za-z0-9%-%_.]+$", "")
    return s
end

--[[
    ============================================================================
    JWT GENERATION
    ============================================================================
--]]

--[[
    Generate a JWT token
    
    @param options: Table with the following fields:
        - header (table, optional): JWT header claims (default: {alg = algorithm, typ = "JWT"})
        - claims (table, required): JWT payload claims
        - algorithm (string, required): e.g. "none", "RS256", "ES256", "HS256"
        - key (string, optional): Private key PEM (for RS/ES algorithms) or secret (for HS algorithms)
                                  Not required for algorithm "none"
    
    @return jwt: Complete JWT string or nil on error
    @return error: Error message if generation failed
    
    Example:
        local jwt, err = JWTUtils.generate({
            header = {alg = "RS256", typ = "JWT", kid = "key-1"},
            claims = {
                sub = "user123",
                name = "John Doe",
                iat = os.time(),
                exp = os.time() + 3600
            },
            algorithm = "RS256",
            key = privateKeyPEM
        })
--]]
function JWTUtils.generate(options)

    -- Validate required parameters
    if not options or not options.claims then
        error("JWTUtils.generate: claims are required")
    end
    
    if not options.algorithm then
        error("JWTUtils.generate: algorithm is required")
    end
    
    local algorithm = options.algorithm
    
    -- Validate algorithm
    if not cryptoLite.isSupportedSignatureAlgorithm(algorithm) then
        error("JWTUtils.generate: unsupported algorithm: " .. algorithm)
    end
    
    -- For signed JWTs, key is required
    if algorithm ~= "none" and not options.key then
        error("JWTUtils.generate: key is required for algorithm: " .. algorithm)
    end
    
    -- Build header
    local header = options.header or {}
    if not header.alg then
        header.alg = algorithm
    end
    if not header.typ then
        header.typ = "JWT"
    end
    
    -- Encode header and claims
    local success, headerJSON = pcall(cjson.encode, header)
    if not success then
        error("JWTUtils.generate: failed to encode header: " .. tostring(headerJSON))
    end
    
    local success, claimsJSON = pcall(cjson.encode, options.claims)
    if not success then
        error("JWTUtils.generate: failed to encode claims: " .. tostring(claimsJSON))
    end
    
    local headerEncoded = cryptoLite.base64URLEncode(headerJSON)
    local claimsEncoded = cryptoLite.base64URLEncode(claimsJSON)
    
    -- Create signature input
    local signatureInput = headerEncoded .. "." .. claimsEncoded
    
    -- Generate signature
    local success, signature = pcall(cryptoLite.sign, signatureInput, options.key, algorithm)
    if not success then
        error("JWTUtils.generate: failed to sign JWT: " .. tostring(signature))
    end
    
    -- Combine into JWT
    return signatureInput .. "." .. signature, nil
end

--[[
    ============================================================================
    JWT VALIDATION
    ============================================================================
--]]

--[[
    Validate a JWT token
    
    @param options: Table with the following fields:
        - jwt (string, required): The JWT string to validate
        - algorithm (string, required): Expected algorithm ("none", "RS256", "ES256", "HS256")
        - key (string, optional): Public key PEM (for RS256/ES256) or secret (for HS256)
                                  Not used for algorithm "none"
                                  Not required if jwks is provided
        - jwks (table, optional): JWKS data structure for key lookup
        - validateExp (boolean, optional): Whether to validate expiration (default: true)
        - clockSkew (number, optional): Clock skew tolerance in seconds (default: 0)
    
    @return result: Table with jwtHeader, jwtClaims or throws an error on failure with an error message
    
    Example:
        local results = JWTUtils.validate({
            jwt = jwtString,
            algorithm = "RS256",
            jwks = jwksData,
            validateExp = true,
            clockSkew = 60
        })
--]]
function JWTUtils.validate(options)

    -- Validate required parameters
    if not options or not options.jwt then
        error("JWTUtils.validate: jwt is required")
    end
    
    if not options.algorithm then
        error("JWTUtils.validate: algorithm is required")
    end
    
    local jwt = options.jwt
    local algorithm = options.algorithm
    local validateExp = options.validateExp
    if validateExp == nil then
        validateExp = true
    end
    local clockSkew = options.clockSkew or 0
    
    -- Split JWT into parts
    -- Handle empty signature part for algorithm "none"
    local parts = {}
    local dotCount = 0
    for i = 1, #jwt do
        if jwt:sub(i, i) == "." then
            dotCount = dotCount + 1
        end
    end
    
    -- JWT should have exactly 2 dots (3 parts: header.claims.signature)
    if dotCount ~= 2 then
        error("JWTUtils.validate: invalid JWT format: expected 2 dots, got " .. dotCount)
    end
    
    -- Split by dots, preserving empty parts
    local startPos = 1
    for i = 1, #jwt do
        if jwt:sub(i, i) == "." then
            table.insert(parts, jwt:sub(startPos, i - 1))
            startPos = i + 1
        end
    end
    -- Add the last part (signature, which may be empty)
    table.insert(parts, jwt:sub(startPos))
    
    local headerEncoded = parts[1]
    local claimsEncoded = parts[2]
    local signatureEncoded = parts[3]
    
    -- Decode header and claims
    local success, headerJSON = pcall(cryptoLite.base64URLDecode, headerEncoded)
    if not success then
        error("JWTUtils.validate: failed to decode header: " .. tostring(headerJSON))
    end
    
    local success, header = pcall(cjson.decode, headerJSON)
    if not success then
        error("JWTUtils.validate: failed to parse header JSON: " .. tostring(header))
    end
    
    local success, claimsJSON = pcall(cryptoLite.base64URLDecode, claimsEncoded)
    if not success then
        error("JWTUtils.validate: failed to decode claims: " .. tostring(claimsJSON))
    end
    
    local success, claims = pcall(cjson.decode, claimsJSON)
    if not success then
        error("JWTUtils.validate: failed to parse claims JSON: " .. tostring(claims))
    end
    
    -- Verify algorithm matches
    if header.alg ~= algorithm then
        error("JWTUtils.validate: algorithm mismatch: expected " .. algorithm .. ", got " .. header.alg)
    end
    
    -- Validate expiration if requested
    if validateExp and claims.exp then
        local currentTime = os.time()
        if claims.exp < (currentTime - clockSkew) then
            error("JWTUtils.validate: JWT expired")
        end
    end
    
    -- Validate not-before if present
    if claims.nbf then
        local currentTime = os.time()
        if claims.nbf > (currentTime + clockSkew) then
            error("JWTUtils.validate: JWT not yet valid")
        end
    end
    
    -- Verify signature
    if algorithm == "none" then
        -- Unsigned JWT - just check signature is empty
        if signatureEncoded ~= "" then
            error("JWTUtils.validate: unsigned JWT should have empty signature")
        end
        return {
            jwtHeader = header, 
            jwtClaims = claims
        }
    end
    
    -- For signed JWTs, we need a key
    local verificationKeys = {}
    
    if options.key then
        -- Direct key provided
        table.insert(verificationKeys, {pem = options.key, kid = nil})
    elseif options.jwks then
        -- Get keys from JWKS
        local kid = header.kid
        verificationKeys = getVerificationKeysFromJWKS(options.jwks, kid, algorithm)
        
        if #verificationKeys == 0 then
            error("JWTUtils.validate: no matching keys found in JWKS")
        end
    else
        error("JWTUtils.validate: key or jwks required for signature verification")
    end
    
    -- Try each verification key
    local signatureBaseString = headerEncoded .. "." .. claimsEncoded
    
    for _, keyInfo in ipairs(verificationKeys) do
        local success, valid = pcall(cryptoLite.verify, signatureBaseString, signatureEncoded, keyInfo.pem, algorithm)
        if success and valid then
            return {
                jwtHeader = header,
                jwtClaims = claims
            }
        end
    end
    
    error("JWTUtils.validate: signature verification failed")
end

--[[
    ============================================================================
    CONVENIENCE FUNCTIONS
    ============================================================================
--]]

--[[
    Decode a JWT without validation (useful for inspecting tokens)
    @param jwt: JWT string
    @return header: Decoded header table or nil
    @return claims: Decoded claims table or nil
    @return error: Error message if decoding failed
--]]
function JWTUtils.decode(jwt)
    if not jwt then
        error("JWTUtils.decode: jwt is required")
    end
    
    -- Split JWT into parts
    -- Handle empty signature part for algorithm "none"
    local parts = {}
    local dotCount = 0
    for i = 1, #jwt do
        if jwt:sub(i, i) == "." then
            dotCount = dotCount + 1
        end
    end
    
    -- JWT should have exactly 2 dots (3 parts: header.claims.signature)
    if dotCount ~= 2 then
        error("JWTUtils.decode: invalid JWT format: expected 2 dots, got " .. dotCount)
    end
    
    -- Split by dots, preserving empty parts
    local startPos = 1
    for i = 1, #jwt do
        if jwt:sub(i, i) == "." then
            table.insert(parts, jwt:sub(startPos, i - 1))
            startPos = i + 1
        end
    end
    -- Add the last part (signature, which may be empty)
    table.insert(parts, jwt:sub(startPos))
    
    -- Decode header
    local success, headerJSON = pcall(cryptoLite.base64URLDecode, parts[1])
    if not success then
        error("JWTUtils.decode: failed to decode header")
    end
    
    local success, header = pcall(cjson.decode, headerJSON)
    if not success then
        error("JWTUtils.decode: failed to parse header JSON")
    end
    
    -- Decode claims
    local success, claimsJSON = pcall(cryptoLite.base64URLDecode, parts[2])
    if not success then
        error("JWTUtils.decode: failed to decode claims")
    end
    
    local success, claims = pcall(cjson.decode, claimsJSON)
    if not success then
        error("JWTUtils.decode: failed to parse claims JSON")
    end
    
    return header, claims, nil
end

--[[
    ============================================================================
    JWE (JSON WEB ENCRYPTION) FUNCTIONS - Simplified Implementation
    ============================================================================
    
    This is a simplified JWE implementation supporting common encryption scenarios:
    - RSA-OAEP for key encryption (RSA public key encryption)
    - ECDH-ES for key agreement (Elliptic Curve Diffie-Hellman) - requires updated luaossl
    - Direct encryption with shared secret
    
    Follows the signed-then-encrypted pattern for nested JWT/JWE
--]]

--[[
    Generate an encrypted JWT (JWE) using signed-then-encrypted pattern
    
    @param options: Table with the following fields:
        - jwt (string, optional): Pre-signed JWT to encrypt. If not provided, will generate one
        - header (table, optional): JWT header for generation (if jwt not provided)
        - claims (table, optional): JWT claims for generation (if jwt not provided)
        - signatureAlgorithm (string, optional): Signature algorithm (if jwt not provided)
        - signatureKey (string, optional): Signing key (if jwt not provided)
        - encryptionAlgorithm (string, required): "RSA-OAEP", "ECDH-ES", or "dir"
        - encryptionKey (string, required): Public key PEM (RSA/EC) or shared secret (dir)
        - encryptionMethod (string, requried): e.g. "A256GCM" - must be a supported content encryption algorithm from CryptoLite
        - kid (string, optional): Key ID for JWE header
        - zip (boolean, optional): whether or not to use zip default compression of the plaintext prior to encryption. Default: false

    
    @return jwe: Encrypted JWT string or throws error
    @return error: Error message if generation failed
    
    Example:
        local jwe, err = JWTUtils.generateEncrypted({
            claims = {sub = "user123", exp = os.time() + 3600},
            signatureAlgorithm = "RS256",
            signatureKey = privateKeyPEM,
            encryptionAlgorithm = "RSA-OAEP",
            encryptionKey = recipientPublicKeyPEM,
            encryptionMethod = "A256GCM",
            zip = true
        })
--]]
function JWTUtils.generateEncrypted(options)
    if not options then
        error("JWTUtils.generateEncrypted: options are required")
    end
    
    if not options.encryptionAlgorithm then
        error("JWTUtils.generateEncrypted: encryptionAlgorithm is required")
    end
    
    if not options.encryptionKey then
        error("JWTUtils.generateEncrypted: encryptionKey is required")
    end
    
    local encAlg = options.encryptionAlgorithm
    
    -- Validate encryption algorithm
    if not cryptoLite.isSupportedEncryptionKeyAgreementAlgorithm(encAlg) then
        error("JWTUtils.generateEncrypted: unsupported encryption algorithm: " .. logger.dumpAsString(encAlg))
    end

        -- Validate encryption method
    local encMethod = options.encryptionMethod
    if not cryptoLite.isSupportedContentEncryptionAlgorithm(encMethod) then
        error("JWTUtils.generateEncrypted: unsupported encryption method: " .. logger.dumpAsString(encMethod))
    end

    -- Step 1: Get or generate the signed JWT
    local jwt
    if options.jwt then
        jwt = options.jwt
    else
        -- Generate signed JWT
        if not options.claims then
            error("JWTUtils.generateEncrypted: claims are required when jwt is not provided")
        end
        
        if not cryptoLite.isSupportedSignatureAlgorithm(options.signatureAlgorithm) then
            error("JWTUtils.generateEncrypted: unsupported signing algorithm: " .. logger.dumpAsString(options.signatureAlgorithm))
        end
        local err
        jwt, err = JWTUtils.generate({
            header = options.header,
            claims = options.claims,
            algorithm = options.signatureAlgorithm,
            key = options.signatureKey
        })
        
        if not jwt then
            error("JWTUtils.generateEncrypted: failed to generate JWT: " .. (err or "unknown error"))
        end
    end
    
    -- Step 2: Encrypt the JWT
    local success, encrypted, plaintext

    -- generate JWE header - required now to figure out additional authentication data
    -- note this does get updated to add the epk when using ECDH-ES as the encryption algorithm
    local jweHeader = {
        alg = encAlg,
        enc = encMethod,
        typ = "JWE",
        cty = "JWT"
    }
    if options.kid then
        jweHeader.kid = options.kid
    end
    if options.zip then
        jweHeader.zip = "DEF"
        plaintext = libDeflate:CompressDeflate(jwt)
    else
        plaintext = jwt
    end
    
    local success, jweHeaderStr = pcall(cjson.encode, jweHeader)
    if not success then
        error("JWTUtils.generateEncrypted: failed to encode JWE header: " .. tostring(jweHeaderStr))
    end
    local jweHeaderB64U = cryptoLite.base64URLEncode(jweHeaderStr)

    if encAlg == "dir" then
        -- Direct encryption with shared secret - not yet supported
        error("JWTUtils.generateEncrypted: direct encryption not supported")
    else
        -- must be an RSA or EC based algorithm

        --
        -- If ECDH based algorithm, generate the ephemeral key first, since we need to create the JWE 
        -- header with the public key in it this should be on the same curve as recipientPublicKeyPEM
        --
        local ephemeralKey = nil
        if cryptoLite.isECDHEncryptionKeyAgreement(encAlg) then
            -- Get the curve name from the recipient's key
            local curveInfo = cryptoLite.determineECKeyProperties(options.encryptionKey)
        
            -- Generate ephemeral key pair on the same curve
            local genParams = {
                type = "EC",
                curve = curveInfo.curveName
            }

            ephemeralKey = pkey.new(genParams)

            -- get the JWK format of the public key of the ephemeralKey to form part of the JWE header
            local epk = cryptoLite.PEMtoJWK(ephemeralKey:toPEM("public"))
            --logger.debugLog("JWTUtils.generateEncrypted epk: " .. logger.dumpAsString(epk))

            -- update the JWE header and its base64-url encoded  representation to include the epk
            jweHeader.epk = epk
            jweHeaderB64U = cryptoLite.base64URLEncode(cjson.encode(jweHeader))
        end

        -- Encrypt the jwt with requested encryption key agreement and content encryption algorithm
        --logger.debugLog("JWTUtils.generateEncrypted: About to call cryptoLite.encrypt: plaintext: " .. logger.dumpAsString(jwt) .. " key: " .. logger.dumpAsString(options.encryptionKey))

        local encryptResults = cryptoLite.encrypt({
            plaintext = plaintext,
            key = options.encryptionKey,
            encryptionKeyAgreement = encAlg,
            contentEncryptionAlgorithm = encMethod,
            apu = jweHeader.apu,
            apv = jweHeader.apv,
            ephemeralKey = ephemeralKey,
            additionalAuthenticatedData = jweHeaderB64U
        })

        -- the encryptedKey will be empty for ECDH-ES as there is no cek keywrap
        local encryptedKeyB64U = ""
        if (encryptResults.encryptedKey) then
            encryptedKeyB64U = cryptoLite.base64URLEncode(encryptResults.encryptedKey)
        end

        -- put the bits together
        encrypted = encryptedKeyB64U .. "." .. cryptoLite.base64URLEncode(encryptResults.iv) .. "." .. cryptoLite.base64URLEncode(encryptResults.ciphertext) .. "." .. cryptoLite.base64URLEncode(encryptResults.tag)        
    end
    
    -- Step 3: Create JWE structure
    -- Format: {base64url(JWE_header)}.{encrypted_jwt}
    
    -- Return JWE format
    local result = jweHeaderB64U .. "." .. encrypted
    --logger.debugLog("JWTUtils.generateEncrypted returning: " .. result)
    return result
end

--[[
    Validate an encrypted JWT (JWE) using decrypt-then-verify pattern
    
    @param options: Table with the following fields:
        - jwe (string, required): The JWE string to decrypt and validate
        - encryptionAlgorithm (string, required): Expected encryption algorithm - currently only "RSA-OAEP" is suported
        - decryptionKey (string, required): Private key PEM (RSA/EC) or shared secret (dir)
        - encryptionMethod (string, required): Expected encryption method - "A256GCM"
        - signatureAlgorithm (string, required): Expected signature algorithm for inner JWT
        - signatureKey (string, optional): Public key PEM or secret for signature verification
        - jwks (table, optional): JWKS for signature verification (alternative to signatureKey)
        - validateExp (boolean, optional): Whether to validate expiration. Default: true
        - clockSkew (number, optional): Clock skew tolerance in seconds. Default: 0
    
    @return result: Table with jweHeader, jwtHeader, jwtClaims or throws an error on failure with an error message
    
    Example:
        local result = JWTUtils.validateEncrypted({
            jwe = jweString,
            encryptionAlgorithm = "RSA-OAEP",
            decryptionKey = privateKeyPEM,
            encryptionMethod = "A256GCM",
            signatureAlgorithm = "RS256",
            signatureKey = publicKeyPEM,
            validateExp = true
        })
--]]
function JWTUtils.validateEncrypted(options)

    if not options or not options.jwe then
        error("JWTUtils.validateEncrypted: jwe is required")
    end
    
    -- Validate encryption algorithm
    local encAlg = options.encryptionAlgorithm
    if not cryptoLite.isSupportedEncryptionKeyAgreementAlgorithm(encAlg) then
        error("JWTUtils.validateEncrypted: unsupported encryption algorithm: " .. logger.dumpAsString(encAlg))
    end

        -- Validate encryption method
    local encMethod = options.encryptionMethod
    if not cryptoLite.isSupportedContentEncryptionAlgorithm(encMethod) then
        error("JWTUtils.validateEncrypted: unsupported encryption method: " .. logger.dumpAsString(encMethod))
    end
    
    if not options.decryptionKey then
        error("JWTUtils.validateEncrypted: decryptionKey is required")
    end
    
    if not cryptoLite.isSupportedSignatureAlgorithm(options.signatureAlgorithm) then
        error("JWTUtils.validateEncrypted: unsupported signing algorithm: " .. logger.dumpAsString(options.signatureAlgorithm))
    end
    
    local jwe = options.jwe
    
    -- Step 1: Parse JWE structure

    local parts = {}
    local dotCount = 0
    for i = 1, #jwe do
        if jwe:sub(i, i) == "." then
            dotCount = dotCount + 1
        end
    end
    
    -- JWE should have exactly 4 dots (5 parts: header.encryptedKey.iv.ciphertext.tag)
    if dotCount ~= 4 then
        error("JWTUtils.validateEncrypted: invalid JWE format: expected 4 dots, got " .. dotCount)
    end
    
    -- Split by dots, preserving empty parts
    local startPos = 1
    for i = 1, #jwe do
        if jwe:sub(i, i) == "." then
            table.insert(parts, jwe:sub(startPos, i - 1))
            startPos = i + 1
        end
    end
    -- Add the last part
    table.insert(parts, jwe:sub(startPos))

    
    local jweHeaderEncoded = parts[1]
    local encryptedKeyEncoded = parts[2]
    local ivEncoded = parts[3]
    local encryptedJWSEncoded = parts[4]
    local tagEncoded = parts[5]
    
    -- Decode components
    local success, jweHeaderJSON = pcall(cryptoLite.base64URLDecode, jweHeaderEncoded)
    if not success then
        error("JWTUtils.validateEncrypted: failed to decode JWE header: " .. tostring(jweHeaderJSON))
    end
    local success, encryptedKey = pcall(cryptoLite.base64URLDecode, encryptedKeyEncoded)
    if not success then
        error("JWTUtils.validateEncrypted: failed to decode encryptedKey: " .. tostring(encryptedKey))
    end
    local success, iv = pcall(cryptoLite.base64URLDecode, ivEncoded)
    if not success then
        error("JWTUtils.validateEncrypted: failed to decode iv: " .. tostring(iv))
    end
    local success, encryptedJWS = pcall(cryptoLite.base64URLDecode, encryptedJWSEncoded)
    if not success then
        error("JWTUtils.validateEncrypted: failed to decode encryptedJWS: " .. tostring(encryptedJWS))
    end
    local success, tag = pcall(cryptoLite.base64URLDecode, tagEncoded)
    if not success then
        error("JWTUtils.validateEncrypted: failed to decode tag: " .. tostring(tag))
    end

    -- process JWE header
    local success, jweHeader = pcall(cjson.decode, jweHeaderJSON)
    if not success then
        error("JWTUtils.validateEncrypted: failed to parse JWE header JSON: " .. tostring(jweHeader))
    end
    
    -- Verify encryption algorithm matches
    if jweHeader.alg ~= encAlg then
        error("JWTUtils.validateEncrypted: encryption algorithm mismatch: expected " .. encAlg .. ", got " .. jweHeader.alg)
    end

    -- Verify encryption method matches
    if jweHeader.enc ~= encMethod then
        error("JWTUtils.validateEncrypted: encryption method mismatch: expected " .. encMethod .. ", got " .. jweHeader.enc)
    end
    
    -- Step 2: Decrypt the JWT
    local jwt
    if encAlg == "dir" then
        error("JWTUtils.validateEncrypted: Direct decryption not supported")
    else
        -- must be an RS or EC algorithm - decrypt the JWE

        -- if this is an ECDH algorithm, then we need the ephemeralPublicKey information to decrypt
        local ephemeralKeyPublicPEM = nil
        if cryptoLite.isECDHEncryptionKeyAgreement(encAlg) then
            -- extract the epk from the JWE header
            if not jweHeader.epk then
                return false, nil, nil, "JWTUtils.validateEncrypted: JWE header missing epk"
            end
            -- and convert PEM
            local success, epkPEM = pcall(cryptoLite.jwkToPEM, jweHeader.epk)
            if not success then
                return false, nil, nil, "JWTUtils.validateEncrypted: Invalid epk: " .. tostring(epkPEM)
            end
            ephemeralKeyPublicPEM = epkPEM
        end

        -- perform decryption of JWS to JWT
        local decryptOptions = {
            ciphertext = encryptedJWS,
            encryptedKey = encryptedKey,
            key = options.decryptionKey,
            encryptionKeyAgreement = encAlg,
            contentEncryptionAlgorithm = encMethod,
            iv = iv,
            tag = tag,
            ephemeralKeyPublicPEM = ephemeralKeyPublicPEM,
            additionalAuthenticatedData = jweHeaderEncoded
        }
        local success, decryptedJWT = pcall(cryptoLite.decrypt, decryptOptions)
        if not success then
            error("JWTUtils.validateEncrypted: Decryption of JWS to JWT failed: " .. tostring(decryptedJWT))
        else
            --logger.debugLog("Decrypted JWS to JWT: " .. logger.dumpAsString(jwt))
        end
        jwt = decryptedJWT
    end

    -- Step 3: If the plaintext is zip'd, deflate it
    if jweHeader.zip == "DEF" then
        --logger.debugLog("JWTUtils.validateEncrypted: Deflating plaintext")
        jwt = libDeflate:DecompressDeflate(jwt)
    end

    -- make sure there is no leading or trailing non-b64u valid characters around the JWT before sending for signature validation
    -- this caters for a situation where the string that was encrypted may have had extra whitespace or a newline after it, etc
    jwt = trimb64u(jwt)
    --logger.debugLog("JWTUtils.validateEncrypted decrypted JWT: " .. logger.dumpAsString(jwt))
    
    -- Step 4: Validate the decrypted JWT
    local validationResults = JWTUtils.validate({
        jwt = jwt,
        algorithm = options.signatureAlgorithm,
        key = options.signatureKey,
        jwks = options.jwks,
        validateExp = options.validateExp,
        clockSkew = options.clockSkew
    })

    -- result is the validation results plus the jweHeader
    validationResults.jweHeader = jweHeader
    return validationResults
end

return JWTUtils

-- Made with Bob
