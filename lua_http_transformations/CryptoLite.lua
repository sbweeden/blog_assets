--[[
Set of crypto functions built on basexx and openssl capabilities
--]]

-- Dependencies
local logger = require 'LoggingUtils'
local baseutils = require 'basexx'
local cipher = require "openssl.cipher"
local rand = require "openssl.rand"
local kdf = require "openssl.kdf"
local pkey = require "openssl.pkey"
local digest = require "openssl.digest"
local hmac = require "openssl.hmac"
local ber = require "ber"
local cjson = require "cjson"

local CryptoLite = {}

local SALT_LENGTH=16 -- bytes

--
-- Only set this to true if you are sure you are using a version of luaossl
-- that is compatible with this CryptoLite library
-- Some features require update from the standard luarocks implementation. The changes are:
--     * Support for additionalAuthenticatedData (AAD) when performing symmetric encrypt/decrypt operations. This is also used by RSA and EC crypto.
--     * Support for ECDH key derivation. This is used with ECDH-ES encryption key agreement
-- Performing the checks for these features (i.e. leaving this set to false) is not expensive and the results are cached, so there is
-- no really good reason to turn it off.
--
local SKIP_FEATURE_TEST = false

--[[
    ============================================================================
    Internal utility functions (not exported)
    ============================================================================
--]]


--[[
    Derives a key from a passphrase using PBKDF2 and the sha256 hash function
    @param passphrase: The passphrase to derive key from
    @param salt: Salt for key derivation (optional, will be generated if not provided)
    @param keyLength: Length of key to derive in bytes (default: 32 for 256-bit)
    @param iterations: Number of iterations (default: 100000)
    @return key, salt: The derived key and salt used
--]]
local function deriveKey(passphrase, salt, keyLength, iterations)
    keyLength = keyLength or 32
    iterations = iterations or 100000
    salt = salt or rand.bytes(SALT_LENGTH)
    
    local params = {
        type = "PBKDF2",
        pass = passphrase,
        salt = salt,
        iter = iterations,
        md = "sha256",
        outlen = keyLength
    }
    local key = kdf.derive(params)
    
    return key, salt
end

--[[
    Removes leading zero bytes from a byte string, whist ensuring the byte string is not truncated 
    below the minLength number of bytes (provided it was at least that long to start with)
    @param data: The byte string to process
    @param minLength: The minimum length the byte string should be truncated to. Optional.
    @return: The byte string with leading zeros removed
--]]
local function removeLeadingZeros(data, minLength)
    local leadingZeros = 0
    for i = 1, #data do
        if data:byte(i) ~= 0 then
            break
        end
        if minLength ~= nil and (#data - leadingZeros <= minLength) then
            break
        end
        leadingZeros = leadingZeros + 1
    end
    return data:sub(leadingZeros + 1)
end

--[[
    Removes leading zero bytes from a byte string, whist ensuring the byte string is not truncated 
    below the minLength number of bytes (provided it was at least that long to start with), then
    adds leading zeros until the length of the byte string is equal to the specified length.
    @param data: The byte string to process
    @param len: The desired length of the resulting byte string
    @return: The byte string padded to the desired length so long as the byte string, after leading zeros are removed,
    is less than or equal to that length
--]]
local function padToLength(data, len)
    local result = removeLeadingZeros(data, len)
    if #result < len then
        result = string.rep("\x00", len - #result) .. result
    end
    return result
end

--[[
    Pads a byte string with a leading zero byte if the leading byte indicates a signed value.
    This ensures proper interpretation of the byte string as an unsigned value by prepending
    0x00 when the leading byte is greater than 127 (0x7F).
    @param n: The byte string to process
    @return: The byte string, optionally padded with a leading zero byte
--]]
local function padIfSigned(n)
    local result = ''
    -- check the leading byte of byte string n, and if it is > 127 then prepend 0x00 to n
    local leadingByte = n:byte(1)
    if (leadingByte > 127) then
        result = "\x00" .. n
    else
        result = n
    end
    return result
end

--[[
    Extracts the r and s components from an OpenSSL EC signature in DER format.
    Decodes the BER-encoded signature and extracts the two INTEGER values (r and s)
    then pads them with leading zeros (or removes padding of leading zeros) to achieve a desired length
    @param sigBytes: The DER-encoded EC signature byte string
    @param requiredByteLength: The length to pad the r and s values to in bytes
    @return r, s: The r and s components as byte strings, or nil, nil if parsing fails
--]]
local function getRandSFromOpenSSLECSignature(sigBytes, requiredByteLength)
    local r = nil
    local s = nil

    local decodeResult = ber.decode(sigBytes)
    if (decodeResult ~= nil and decodeResult["class"] == 0 and decodeResult["type"] == 16 and decodeResult["data"] ~= nil
        and decodeResult["children"] ~= nil and #decodeResult["children"] == 2
        and decodeResult["children"][1] ~= nil and decodeResult["children"][2] ~= nil
        and decodeResult["children"][1]["class"] == 0 and decodeResult["children"][2]["class"] == 0
        and decodeResult["children"][1]["type"] == 2 and decodeResult["children"][2]["type"] == 2
    ) then
        r = decodeResult["children"][1]["data"]
        s = decodeResult["children"][2]["data"]

        if (#r ~= requiredByteLength) then
            r = padToLength(r, requiredByteLength)
        end
        if (#s ~= requiredByteLength) then
            s = padToLength(s, requiredByteLength)
        end
    else
        logger.debugLog("CryptoLite:getRandSFromOpenSSLECSignature unexpected decodeResult")
    end

    return r, s
end

--[[
    Constructs an OpenSSL EC signature in DER format from r and s components.
    Removes leading zeros from r and s and then pads if needed (when leading byte > 127), encodes them as BER INTEGERs,
    and wraps them in a BER SEQUENCE. This reverses the steps of getRandSFromOpenSSLECSignature().
    @param r: The r component as a byte string
    @param s: The s component as a byte string
    @return: The DER-encoded EC signature byte string
--]]
local function getOpenSSLECSignatureFromRandS(r,s)
    local finalR = padIfSigned(removeLeadingZeros(r))
    local finalS = padIfSigned(removeLeadingZeros(s))

    local berR = ber.encode({ 
        type = ber.Types.INTEGER,
        data = finalR
    })
    local berS = ber.encode({ 
        type = ber.Types.INTEGER,
        data = finalS
    })
    local berSeq = ber.encode({ 
    type = ber.Types.SEQUENCE,
        data = berR .. berS
     })

    return berSeq
end

--[[
    Decodes an ASN.1 Object Identifier (OID) from its DER-encoded byte string representation
    into a dotted-decimal string (e.g. "1.2.840.10045.3.1.7").
    The first byte encodes the first two subidentifiers using the formula (X * 40) + Y.
    Subsequent subidentifiers are encoded using base-128 (variable-length) encoding.
    @param oidBytes: The raw DER-encoded OID value bytes (excluding the tag and length bytes)
    @return: The OID as a dotted-decimal string (e.g. "1.2.840.10045.3.1.7")
--]]
local function decodeASN1ObjectIdentifier(oidBytes)
    local result = nil
    local resultStr = ""

    if not oidBytes then
        error("CryptoLite.decodeASN1ObjectIdentifier oidBytes not provided")
    end

    -- The first byte of the OID value encodes the first two subidentifiers into a single value using the formula 
    -- (X * 40) + Y, where X is the first subidentifier (0, 1, or 2) and Y is the second (0-39 for X=0, 0-39 for 
    -- X=1, and 0 to potentially much larger values for X=2).
    resultStr = resultStr .. tostring(math.floor(string.byte(oidBytes, 1) / 40)) .. "." .. tostring(math.floor(string.byte(oidBytes, 1) % 40))
    
    -- The remaining bytes in the OID value encode the subsequent subidentifiers. Each subidentifier is encoded 
    -- using a variable number of 7-bit bytes (base 128 encoding). Iterate through the bytes starting from the second byte.
    -- For each series of bytes representing a single subidentifier:
    --    Each byte, except the last one, has its most significant bit (MSB, bit 8) set to 1 (e.g., 0x80 or higher).
    --    The last byte of the series has its MSB set to 0.
    --    The actual value of the subidentifier is encoded in the remaining 7 bits of each byte, concatenated together in order.
    local subidVal = 0
    for i = 2, #oidBytes do
        -- is this the last byte in the subidentifier?
        if string.byte(oidBytes, i) < 128 then
            -- this is the last byte in the subidentifier, wrap it up
            subidVal = (subidVal*128) + string.byte(oidBytes, i)
            resultStr = resultStr .. "." .. tostring(subidVal)
            subidVal = 0
        else
            -- this is part of the subidentifier, but not the last byte since MSB is set
            subidVal = (subidVal*128) + (string.byte(oidBytes, i) - 128)
        end
    end

    -- anything left over - should not happen
    if subidVal > 0 then
        error("CryptoLite.decodeASN1ObjectIdentifier: invalid DER encoding of Object Identifier")
    end
    return resultStr
end

--[[
    ============================================================================
    ENCODING/DECODING FUNCTIONS (Public APIs)
    ============================================================================
--]]

--[[
    Base64 encode a string
    @param data: The data to encode
    @return encoded: Base64-encoded string
--]]
function CryptoLite.base64Encode(data)
    return baseutils.to_base64(data)
end

--[[
    Base64 decode a string
    @param data: Base64-encoded string
    @return decoded: Decoded string
--]]
function CryptoLite.base64Decode(data)
    return baseutils.from_base64(data)
end

--[[
    Base64URL encode a string (URL-safe base64 encoding used in JWT)
    @param data: The data to encode
    @return encoded: Base64URL-encoded string
--]]
function CryptoLite.base64URLEncode(data)
    return baseutils.to_url64(data)
end

--[[
    Base64URL decode a string (URL-safe base64 decoding used in JWT)
    @param data: Base64URL-encoded string
    @return decoded: Decoded string
--]]
function CryptoLite.base64URLDecode(data)
        return baseutils.from_url64(data)
end

--[[
    Produce a byte string represenation of the bytes in the array
    @param byteArray: array of integer byte values
    @return byteString: byte string of these bytes
--]]
function CryptoLite.BAtoByteString(byteArray)
    local result = ""
    for _, v in ipairs(byteArray) do
        result = result .. string.char(v)
    end
    return result
end

--[[
    Produce a byte array represenation of the bytes in the string byteString
    @param byteString: byte string of these bytes
    @return byteArray: array of integer byte values
--]]
function CryptoLite.ByteStringtoBA(byteString)
    local result = {}
    for i = 1, #byteString do
        table.insert(result, string.byte(byteString, i))
    end
    return result
end

--[[
    Produce a lowercase hex string represenation of the bytes in the array
    @param byteArray: array of integer byte values
    @return hex: hex string of these bytes
--]]
function CryptoLite.BAtohex(byteArray)
    return string.lower(baseutils.to_hex(CryptoLite.BAtoByteString(byteArray)))
end

--[[
    Produce an array of bytes from a hex string
    @param hex: hex string (e.g., "48656c6c6f" for "Hello")
    @return byteArray: Array of integer byte values (e.g., {72, 101, 108, 108, 111})
--]]
function CryptoLite.hextoBA(hex)
    return CryptoLite.ByteStringtoBA(baseutils.from_hex(hex))
end 

--[[
    Produce a lowercase hex string represenation of the bytes in the byte string
    @param byteString: byte string
    @return hex: hex string of these bytes
--]]
function CryptoLite.ByteStringtohex(byteString)
    return string.lower(baseutils.to_hex(byteString))
end

--[[
    Produce a byte string from the hex string
    @param hex: hex string
    @return byteString: byte string of the hex bytes
--]]
function CryptoLite.hextoByteString(hex)
    return baseutils.from_hex(hex)
end

--[[
    Produce an array of bytes from the utf-8 chars in the string
    @param str: string to extract utf-8 bytes
    @return array: utf-8 bytes of the string as an array
--]]
function CryptoLite.utf8toBA(str)
    return { string.byte(str, 1, -1) }
end

--[[
    Produce a string from an array of bytes
    @param byteArray: array of utf-8 bytes of the string
    @return str: string to from the utf-8 bytes
--]]
function CryptoLite.BAtoutf8(byteArray)
    local char_array = {}
    for i, v in ipairs(byteArray) do
        char_array[i] = string.char(v)
    end
    return table.concat(char_array)
end

--[[
    ============================================================================
    Feature support - allows you to detect if the luaossl you are running has
    the features required for all of the functions in this library to work
    ============================================================================
--]]

local hasAADSSupportBeenTested = false
local aadSupportResult = false

local function hasAADSupport()
    if hasAADSSupportBeenTested then
        --logger.debugLog("CryptoLite.hasAADSupport has already been tested - using cached result: " .. tostring(aadSupportResult))
        return aadSupportResult
    else
        --logger.debugLog("CryptoLite.hasAADSupport has not been tested - testing now")
    end
    
    --
    -- These are just some well-known static test parameters used to figure out if AAD support exists in the luaossl library
    --
    local testKey = CryptoLite.hextoByteString("e00d4fd399fe82b00d80dff8b9136eeef9d8f27a5e0b268fd61bec90ccbb49db")
    local testPlaintext = "plaintext"
    local testAAD = "aad"
    local testContentEncryptionAlgorithm = "A256GCM"
    local testIV = CryptoLite.hextoByteString("0102030405060708090a0b0c")

    local expectedCiphertextHex = "4ffec603587cdbfffd"
    local expectedTagHex = "931c88ed179265295b0c9f83d514600a"

    -- Create cipher
    local c = cipher.new("aes-256-gcm")

    -- try encryption with the aad
    local result = false
    local success, encryptResult = pcall(
        function()
            return c:encrypt(testKey, testIV, true, testAAD)
        end
    )
    if success then
        -- check the encryption results
        local success, ciphertext = pcall(
            function()
                return c:final(testPlaintext)
            end
        )

        if success then
            local success, tag = pcall(
                function()
                    return c:getTag(16)
                end
            )

            if success then
                ciphertextHex = CryptoLite.ByteStringtohex(ciphertext)
                tagHex = CryptoLite.ByteStringtohex(tag)
                result = (ciphertextHex == expectedCiphertextHex) and (tagHex == expectedTagHex)
                if not result then
                    --logger.debugLog("CryptoLite.hasAADSupport ciphertext and tag checking failed - the luaossl library does not support AAD")
                end
            else
                --logger.debugLog("CryptoLite.hasAADSupport error calling c:getTag : " .. logger.dumpAsString(tag))
                result = false
            end
        else
            --logger.debugLog("CryptoLite.hasAADSupport error calling c:final : " .. logger.dumpAsString(ciphertext))
            result = false
        end
    else
        --logger.debugLog("CryptoLite.hasAADSupport error calling c:encrypt : " .. logger.dumpAsString(encryptResult))
        result = false
    end

    hasAADSSupportBeenTested = true
    aadSupportResult = result
    --logger.debugLog("CryptoLite.hasAADSupport : " .. tostring(result))

    return result
end

local hasECDervieSupportBeenTested = false
local ecSupportResult = false

local function hasECDeriveSupport()

    if hasECDervieSupportBeenTested then
        --logger.debugLog("CryptoLite.hasECDeriveSupport has already been tested - using cached result: " .. tostring(ecSupportResult))
        return ecSupportResult
    else
        --logger.debugLog("CryptoLite.hasECDeriveSupport has not been tested - testing now")
    end

    local testkey1Private = [[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgEv8TBhSAipKRurFz
ITedeEp0LDZP3a6hh8WkGoCdyZOhRANCAASuLyzZKPcff0glTw9ikAerA1Wm/QyY
vob/HPjtwNJuKTPYYratMLGOvg2S0FfbbNiJgdQjknQUFoENanrCG4lF
-----END PRIVATE KEY-----
]]

    local testkey2Public = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaOY0O1psvOqNJpjDJSb0KfziXn7o
Xw2FKrGekoCnvva0iUyh2sgmTiGMm2gCfJTpHAQYxGp+qCJzda+96mIc0w==
-----END PUBLIC KEY-----    
]]
    local expectedSharedSecretHex = "3f119a881d39f4128a1b4c84197d12158507b5b26b27b3493dc253a69dde7476"

    key1 = pkey.new(testkey1Private)
    key2 = pkey.new(testkey2Public)
    local ok, sharedSecret = pcall(
        function()
            return key1:derive(key2)
        end
    )
    if ok then
        -- check the result
        ok = CryptoLite.ByteStringtohex(sharedSecret) == expectedSharedSecretHex
        if (not ok) then
            --logger.debugLog("CryptoLite.hasECDeriveSupport sharedSecret check failed - the luaossl library does not support ECDH")
        end
    else
        --logger.debugLog("CryptoLite.hasECDeriveSupport failed to call cipher:derive - the luaossl library does not support ECDH")
    end

    hasECDervieSupportBeenTested = true
    ecSupportResult = ok

    --logger.debugLog("CryptoLite.hasECDeriveSupport : " .. tostring(ok))
    return ok
end

function CryptoLite.checkFeatures()
    local result = {}
    result.hasAADSupport = hasAADSupport()
    result.hasECDeriveSupport = hasECDeriveSupport()
    return result
end

--[[
    ============================================================================
    UTILITY FUNCTIONS FOR HASH, RANDOM, and concatKDF (Public APIs)
    ============================================================================
--]]

--[[
    Utility function to hash a string using SHA-256
    @param data: The string to hash
    @return hash: Base64URL-encoded hash
--]]
function CryptoLite.sha256(data)
    local md = digest.new("sha256")
    local hash = md:final(data)
    return CryptoLite.base64URLEncode(hash)
end

--[[
    Utility function to generate random bytes
    @param length: Number of random bytes to generate
    @return bytes: Random bytes as a string
--]]
function CryptoLite.randomBytes(length)
    return rand.bytes(length)
end

--[[
    Implements the Concat KDF algorithm as defined in RFC7518 Section 4.6.2
    and NIST SP 800-56A Rev. 3
    
    This is used for key derivation in JWE with ECDH-ES key agreement.
    
    @param options: Table with the following fields:
        - sharedSecret (string, required): The shared secret (Z) from key agreement
        - keyDataLen (number, required): The desired output key length in bits
        - algorithm (string, required): The algorithm identifier value as a string (e.g., "A256GCM")
        - apu (base64url encoded string, optional): Agreement PartyUInfo
        - apv (base64url encoded string, optional): Agreement PartyVInfo
    @return derivedKey: The derived key material
--]]
function CryptoLite.concatKDF(options)

    local sharedSecret = options.sharedSecret
    local keyDataLen = options.keyDataLen
    local algorithm = options.algorithm
    local apu = options.apu
    local apv = options.apv

    -- Validate inputs
    if not sharedSecret or #sharedSecret == 0 then
        error("CryptoLite.concatKDF: sharedSecret is required")
    end
    if not keyDataLen or keyDataLen <= 0 then
        error("CryptoLite.concatKDF: keyDataLen must be positive")
    end
    if not algorithm or #algorithm == 0 then
        error("CryptoLite.concatKDF: algorithm is required")
    end

    -- Convert keyDataLen from bits to bytes
    local keyDataLenBytes = math.ceil(keyDataLen / 8)
    
    -- Decode APU and APV if provided (they should be base64url encoded)
    local apuBytes = ""
    local apvBytes = ""
    if apu and #apu > 0 then
        apuBytes = baseutils.from_url64(apu)
    end
    if apv and #apv > 0 then
        apvBytes = baseutils.from_url64(apv)
    end
    
    -- Build OtherInfo as per NIST SP 800-56A Rev. 3, Section 5.8.1.2
    -- OtherInfo = AlgorithmID || PartyUInfo || PartyVInfo || KeyDataLen
    
    -- AlgorithmID: length (4 bytes, big-endian) || algorithm string
    local algorithmID = string.pack(">I4", #algorithm) .. algorithm
    
    -- PartyUInfo: length (4 bytes, big-endian) || APU data
    local partyUInfo = string.pack(">I4", #apuBytes) .. apuBytes
    
    -- PartyVInfo: length (4 bytes, big-endian) || APV data
    local partyVInfo = string.pack(">I4", #apvBytes) .. apvBytes
    
    -- KeyDataLen: 4 bytes, big-endian, in bits
    local keyDataLenField = string.pack(">I4", keyDataLen)
    
    -- Concatenate all parts and then call openssl kdf with type SSKDF
    local otherInfo = algorithmID .. partyUInfo .. partyVInfo .. keyDataLenField    

    local params = {
        type = "SSKDF",
        secret = sharedSecret,
        outlen = keyDataLenBytes,
        -- for JWE, the hash algorithm used for concatKDF is always sha256 and does not change based on the curve
        md = "sha256",
        info = otherInfo
    }
    local key = kdf.derive(params)

    return key
end

--[[
    ============================================================================
    Asymmetric key generation
    ============================================================================
--]]

--[[
    Generate RSA key pair
    @param bits: Key size in bits (default: 2048, recommended: 2048 or 4096)
    @return publicKeyPEM, privateKeyPEM: The generated key pair in PEM format
--]]
function CryptoLite.generateRSAKeyPair(bits)
    bits = bits or 2048

    local genParams = {
        type = "RSA",
        bits = bits,
        e = 65537
    }
    
    local key = pkey.new(genParams)
    local publicKeyPEM = key:toPEM("public")
    local privateKeyPEM = key:toPEM("private")
    
    return publicKeyPEM, privateKeyPEM
end

--[[
    Generate ECDSA key pair
    @param curve: Curve name (default: "prime256v1", options: "prime256v1", "secp384r1", "secp521r1")
    @return publicKeyPEM, privateKeyPEM: The generated key pair in PEM format
--]]
function CryptoLite.generateECDSAKeyPair(curve)
    curve = curve or "prime256v1"

    local genParams = {
        type = "EC",
        curve = curve
    }
    
    local key = pkey.new(genParams)
    local publicKeyPEM = key:toPEM("public")
    local privateKeyPEM = key:toPEM("private")
    
    return publicKeyPEM, privateKeyPEM
end

--[[
    ============================================================================
    DIGITAL SIGNATURE / VALIDATION FUNCTIONS (JWT-compatible: RS256, ES256, HS256)
    ============================================================================
--]]

--[[
    Get algorithm configuration for supported signing algorithms
    @param algorithm: Algorithm name (e.g., "RS256", "RS256", "ES256")
    @return config: Table with signing parameters
--]]
local function getSignatureAlgorithmConfig(algorithm)
    local configs = {
        ["none"] = { type = "none" },
        ["HS256"] = { type = "HMAC", md = "sha256" },
        ["HS384"] = { type = "HMAC", md = "sha384" },
        ["HS512"] = { type = "HMAC", md = "sha512" },
        ["RS256"] = { type = "RSA", md = "sha256" },
        ["RS384"] = { type = "RSA", md = "sha384" },
        ["RS512"] = { type = "RSA", md = "sha512" },
        ["ES256"] = { type = "ES", md = "sha256", keyLenBits = 256 },
        ["ES384"] = { type = "ES", md = "sha384", keyLenBits = 384 },
        ["ES512"] = { type = "ES", md = "sha512", keyLenBits = 528 }
    }
    
    local config = configs[algorithm]
    if not config then
        local keyset = {}
        for k,v in pairs(configs) do
            table.insert(keyset, k)
        end

        error("CryptoLite.getSignatureAlgorithmConfig unsupported algorithm: " .. algorithm .. ". Supported alorithms: " .. cjson.encode(keyset))
    end
    
    return config
end

--[[
    Checks whether the given algorithm identifier is a supported signing algorithm.
    Supported algorithms are: "none", "HS256", "HS384", "HS512", "RS256", "RS384", "RS512",
    "ES256", "ES384", "ES512".
    @param algorithm: The signing algorithm identifier string to check (e.g. "RS256", "ES256", "HS256")
    @return: true if the algorithm is supported, false otherwise
--]]
function CryptoLite.isSupportedSignatureAlgorithm(algorithm)
    local success, config = pcall(getSignatureAlgorithmConfig, algorithm)
    if (success) then
        return true
    else
        return false
    end
end

--[[
    Get EC curve information from the PEM of either the key (public or private) or the ECParameters
    @param pem: pem of key or ecparameters
    @return curveInfo: Table with curve information
--]]
function CryptoLite.determineECKeyProperties(pem)
    --logger.debugLog("CryptoLite.determineECKeyProperties pem: " .. logger.dumpAsString(pem))

    local oidToCurveInfo = {
        --  1.2.840.10045.3.1.7 prime256v1 / secp256r1
        ["1.2.840.10045.3.1.7"] = { keyLenBits = 256, curveName = "prime256v1" },
        -- 1.3.132.0.34 secp384r1
        ["1.3.132.0.34"] = { keyLenBits = 384, curveName = "secp384r1" },
        -- 1.3.132.0.35 secp521r1
        ["1.3.132.0.35"] = { keyLenBits = 528, curveName = "secp521r1" }
    }

    -- PEM can be either an EC private or public key PEM, or the PEM of the EC paramaters
    local ecParametersPEM = nil
    if (pem:match("%-%-%-%-%-BEGIN EC PARAMETERS%-%-%-%-%-\n(.-)%-%-%-%-%-END EC PARAMETERS%-%-%-%-%-") ~= nil) then
        ecParametersPEM = pem
    else
        -- it better be a EC public or private key PEM
        local k = pkey.new(pem)
        if not k then
            error("CryptoLite.determineECKeyProperties: invalid PEM")
        end
        ecParams = k:getParameters()
        ecParametersPEM = ecParams.group:toPEM()
    end

    local b64 = ecParametersPEM:match("%-%-%-%-%-BEGIN EC PARAMETERS%-%-%-%-%-\n(.-)%-%-%-%-%-END EC PARAMETERS%-%-%-%-%-")
    if not b64 then
        error("CryptoLite.determineECKeyProperties invalid ec parameters PEM format")
    end
    
    -- Remove whitespace and decode
    b64 = b64:gsub("%s+", "")
    local der = CryptoLite.base64Decode(b64)
    
    -- Parse EC PARAMETERS structure, which is an OID    
    local decoded = ber.decode(der)
    if not decoded or decoded.type ~= ber.Types.OBJECT_IDENTIFIER then
        error("CryptoLite.determineECKeyProperties invalid ec parameters structure")
    end

    local curveOID = decodeASN1ObjectIdentifier(decoded.data)
    if not curveOID then
        error("CryptoLite.determineECKeyProperties unable to determine curveOID")
    end
    local curveInfo = oidToCurveInfo[curveOID]
    if not curveInfo then
        error("CryptoLite.determineECKeyProperties unrecognized ec parameters curve OID: " .. curveOID)
    end

    return curveInfo
end

--[[
    Symmetric signing using HMAC
    @param data: data to sign
    @param key: secret key/password to sign with
    @param config: algorithm configuration info
    @return signature: base64url encoded signature of data using key
--]]
local function signHMAC(data, key, config)
    -- Create HMAC with appropriate hash function
    local h = hmac.new(key, config.md)
    local signature = h:final(data)
    
    return CryptoLite.base64URLEncode(signature)
end

--[[
    Symmetric signature verification using HMAC
    @param data: data to verify
    @param signature: signature to verify
    @param key: secret key/password
    @param config: algorithm configuration info
    @return valid: Boolean indicating if signature was valid
--]]
local function verifyHMAC(data, signature, secret, config)
    -- Compute expected signature
    local expectedSignature = signHMAC(data, secret, config)
    
    -- Constant-time comparison to prevent timing attacks
    local sig = CryptoLite.base64URLDecode(signature)
    local expected = CryptoLite.base64URLDecode(expectedSignature)
    
    if #sig ~= #expected then
        return false
    end
    
    local result = 0
    for i = 1, #sig do
        result = result | (string.byte(sig, i) ~ string.byte(expected, i))
    end
    
    return result == 0
end

--[[
    Asymmetric signing using RSA
    @param data: data to sign
    @param key: RSA key to sign with
    @param config: algorithm configuration info
    @return signature: base64url encoded signature of data using key
--]]
local function signRSA(data, key, config)
    -- Load private key
    local privKey = pkey.new(key)
    
    -- Create digest of the data
    local md = digest.new(config.md)
    
    -- Sign the hash of data
    local signature = privKey:sign(md:update(data))
    
    return CryptoLite.base64URLEncode(signature)
end

--[[
    Asymmetric signature verification using RSA
    @param data: data to verify
    @param signature: signature to verify
    @param key: public key
    @param config: algorithm configuration info
    @return valid: Boolean indicating if signature was valid
--]]
local function verifyRSA(data, signature, key, config)
    -- Decode signature from base64url
    local sig = CryptoLite.base64URLDecode(signature)
    
    -- Load public key
    local pubKey = pkey.new(key)
    
    -- Create digest of the data
    local md = digest.new(config.md)
    
    -- Verify signature
    local valid = pubKey:verify(sig, md:update(data))
    
    return valid
end

--[[
    Asymmetric signing using ECDSA
    @param data: data to sign
    @param key: EC key to sign with
    @param config: algorithm configuration info
    @return signature: base64url encoded signature of data using key
--]]
local function signES(data, key, config)
    -- Load private key
    local privKey = pkey.new(key)
    
    -- Create digest of the data
    local md = digest.new(config.md)
    
    -- Sign the hash of data
    local sigBytes = privKey:sign(md:update(data))

    -- determine key length
    ecParams = privKey:getParameters()

    local curveInfo = CryptoLite.determineECKeyProperties(ecParams.group:toPEM())
    if not curveInfo then
        error("CryptoLite.signES unable to determine curve information")
    end

    -- extract R, S without padding from the OpenSSL formatted signature
    -- then concatenate and base64urlencode to create JWT signature
    local requiredByteLength = (curveInfo.keyLenBits/8)
    local r, s = getRandSFromOpenSSLECSignature(sigBytes, requiredByteLength)
    
    return CryptoLite.base64URLEncode(r .. s)
end

--[[
    Asymmetric signature verification using ECDSA
    @param data: data to verify
    @param signature: signature to verify
    @param key: public key
    @param config: algorithm configuration info
    @return valid: Boolean indicating if signature was valid
--]]
local function verifyES(data, signature, key, config)
    -- Re-create OpenSSL compatible signature format from JWT signature format
    local sig = CryptoLite.base64URLDecode(signature)
    local expectedSignatureLength = math.floor(config.keyLenBits/8*2)
    if (#sig ~= expectedSignatureLength) then
        error("CryptoLite.verifyES: invalid signature length")
    end
    -- signature is r .. s and they should be the same size
    local r = string.sub(sig, 1, (expectedSignatureLength/2))
    local s = string.sub(sig, (expectedSignatureLength/2+1), expectedSignatureLength)
    local opensslSig = getOpenSSLECSignatureFromRandS(r,s)

    -- Load public key
    local pubKey = pkey.new(key)
    
    -- Create digest
    local md = digest.new(config.md)
    
    -- Verify signature over digest of the data

    local success, valid = pcall(
        function() 
            return pubKey:verify(opensslSig, md:update(data))
        end
    )
    if not success then
        logger.debugLog("CryptoLite.verifyES: verify failed with error: " .. logger.dumpAsString(valid))
        valid = false
    end
    
    return valid
end

--[[
    Digitally sign data with key using algorithm
    @param data: data to sign
    @param key: key to sign with
    @param alg: name of signature algorithm. Valid values: "HS256", "RS256", "ES256"
    @return signature: base64url encoded signature of data using key
--]]
function CryptoLite.sign(data, key, alg)
    local config = getSignatureAlgorithmConfig(alg)

    if not config then
        error("CryptoLite.sign unsupported alg: " .. alg)
    end

    if config.type == "HMAC" then
        return signHMAC(data, key, config)
    elseif config.type == "RSA" then
        return signRSA(data, key, config)
    elseif config.type == "ES" then
        return signES(data, key, config)
    elseif config.type == "none" then
        return ""
    else
        -- should never happen
        error("CryptoLite.sign unsupported alg: " .. alg)
    end
end

--[[
    Digitally verify sign data with key using algorithm
    @param data: data to verify
    @param signature: signature to verify
    @param key: key to verify with
    @param alg: name of signature algorithm. Valid values are same as CryptoLite.sign
    @return valid: Boolean indicating if signature was valid
--]]
function CryptoLite.verify(data, signature, key, alg)
    local config = getSignatureAlgorithmConfig(alg)
    if not config then
        error("CryptoLite.verify unsupported alg: " .. alg)
    end
    if config.type == "HMAC" then
        return verifyHMAC(data, signature, key, config)
    elseif config.type == "RSA" then
        return verifyRSA(data, signature, key, config)
    elseif config.type == "ES" then
        return verifyES(data, signature, key, config)
    elseif config.type == "none" then
        return (signature == nil or signature == "")
    else
        -- should never happen
        error("CryptoLite.verify unsupported alg: " .. alg)
    end
end

--[[
    ============================================================================
    Symmetric key encryption and decryption
    ============================================================================
--]]

local function getRSAPadding(rsaPaddingStr)
    local configs = {
        ["RSA_PKCS1_PADDING"] = pkey.RSA_PKCS1_PADDING,
        ["RSA_PKCS1_OAEP_PADDING"] = pkey.RSA_PKCS1_OAEP_PADDING
    }
    
    local config = configs[rsaPaddingStr]
    if not config then
        local keyset = {}
        for k,v in pairs(configs) do
            table.insert(keyset, k)
        end

        error("CryptoLite.getRSAPadding unsupported padding: " .. rsaPaddingStr .. ". Supported alorithms: " .. cjson.encode(keyset))
    end

    return config
end


--[[
    Get algorithm configuration for supported symmetric encryption algorithms
    @param algorithm: Algorithm name per JWA (https://datatracker.ietf.org/doc/html/rfc7518) (e.g., "A256GCM", "A128CBC-HS256")
    @return config: Table with keyLength, ivLength, tagLength, isGCM and isAES_CBC_HMAC_SHA2 fields
--]]
local function getContentEncryptionAlgorithmConfig(algorithm)
    local configs = {
        ["A128GCM"] = { jwaName = "A128GCM", osslName = "aes-128-gcm", md = "sha256", keyLength = 16, ivLength = 12, tagLength = 16, isGCM = true, isAES_CBC_HMAC_SHA2 = false },
        ["A192GCM"] = { jwaName = "A192GCM", osslName = "aes-192-gcm", md = "sha256", keyLength = 24, ivLength = 12, tagLength = 16, isGCM = true, isAES_CBC_HMAC_SHA2 = false },
        ["A256GCM"] = { jwaName = "A256GCM", osslName = "aes-256-gcm", md = "sha256", keyLength = 32, ivLength = 12, tagLength = 16, isGCM = true, isAES_CBC_HMAC_SHA2 = false },
        ["A128CBC-HS256"] = { jwaName = "A128CBC-HS256", osslName = "aes-128-cbc", md = "sha256", keyLength = 32, ivLength = 16, tagLength = 16, isGCM = false, isAES_CBC_HMAC_SHA2 = true },
        ["A192CBC-HS384"] = { jwaName = "A192CBC-HS384", osslName = "aes-192-cbc", md = "sha384", keyLength = 48, ivLength = 16, tagLength = 24, isGCM = false, isAES_CBC_HMAC_SHA2 = true },
        ["A256CBC-HS512"] = { jwaName = "A256CBC-HS512", osslName = "aes-256-cbc", md = "sha512", keyLength = 64, ivLength = 16, tagLength = 32, isGCM = false, isAES_CBC_HMAC_SHA2 = true }
    }
    
    local config = configs[algorithm]
    if not config then
        local keyset = {}
        for k,v in pairs(configs) do
            table.insert(keyset, k)
        end

        error("CryptoLite.getContentEncryptionAlgorithmConfig unsupported algorithm: " .. algorithm .. ". Supported alorithms: " .. cjson.encode(keyset))
    end
    
    return config
end

--[[
    Checks whether the given algorithm identifier is a supported JWE content encryption algorithm.
    Supported algorithms are: "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512".
    Unlike getContentEncryptionAlgorithmConfig, this function does not raise an error for unsupported algorithms;
    it returns false instead.
    @param algorithm: The content encryption algorithm identifier string to check (e.g. "A256GCM", "A128CBC-HS256")
    @return: true if the algorithm is supported, false otherwise
--]]
function CryptoLite.isSupportedContentEncryptionAlgorithm(algorithm)
    local success, config = pcall(getContentEncryptionAlgorithmConfig, algorithm)
    if (success) then
        return true
    else
        return false
    end
end


--[[
    Symmetric Encryption using configurable algorithm returning salt, iv, tag (for GCM) and ciphertext as separate binary string fields
    
    This function encrypts plaintext using symmetric encryption algorithms (AES-GCM or AES-CBC).
    If the provided key is shorter than required, it will be derived using PBKDF2 with a generated salt.
    
    @param options: Table with the following fields:
        - plaintext (string, required): The string to encrypt
        - key (string, required): Encryption key. If less than required key length, will be derived using PBKDF2 with salt
        - contentEncryptionAlgorithmConfig (table, required): Config from getContentEncryptionAlgorithmConfig
        - iv (string, optional): IV bytes. Will be generated if not supplied
        - additionalAuthenticatedData (string, optional): Additional authenticated data
    @return result: Table with salt (GCM only), iv, tag, ciphertext fields as binary strings
--]]
local function encryptSymmetricEx(options)

    local plaintext = options.plaintext
    local key = options.key
    local additionalAuthenticatedData = options.additionalAuthenticatedData
    local contentEncryptionAlgorithmConfig = options.contentEncryptionAlgorithmConfig

    if not plaintext or not key or not contentEncryptionAlgorithmConfig then
        error("CryptoLite.encryptSymmetricEx: plaintext, key and algorithm configuration are required")
    end

    -- Use provided or generate random IV
    local ivBytes = options.iv or rand.bytes(contentEncryptionAlgorithmConfig.ivLength)

    -- If this is a AES_CBC_HMAC_SHA2 cipher, the key length must be correct
    if contentEncryptionAlgorithmConfig.isAES_CBC_HMAC_SHA2 then
        if #key ~= contentEncryptionAlgorithmConfig.keyLength then
            error("CryptoLite.encryptSymmetricEx: key length must be " .. tostring(contentEncryptionAlgorithmConfig.keyLength) .. " for AES_CBC_HMAC_SHA2 cipher")
        end
    end
    
    local encKey, macKey, salt
    if (contentEncryptionAlgorithmConfig.isGCM) then
        -- Derive a proper key if needed (GCM only)
        if #key < contentEncryptionAlgorithmConfig.keyLength then
            encKey, salt = deriveKey(key, nil, contentEncryptionAlgorithmConfig.keyLength)
        else
            encKey = key:sub(1, contentEncryptionAlgorithmConfig.keyLength)
            salt = rand.bytes(SALT_LENGTH)
        end
    elseif (contentEncryptionAlgorithmConfig.isAES_CBC_HMAC_SHA2) then
        -- Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-5.2

        -- macKey is the first half of the key
        local halfLen = math.ceil(#key/2)
        macKey = key:sub(1, halfLen)
        -- encKey is the second half
        encKey = key:sub(halfLen + 1, -1)
    else
        -- impossible
        error("CryptoLite.encryptSymmetricEx: contentEncryptionAlgorithm was neither GCM nor AES_CBC_HMAC_SHA2")
    end
        
    -- Create cipher
    local c = cipher.new(contentEncryptionAlgorithmConfig.osslName)
    
    -- Encrypt
    if contentEncryptionAlgorithmConfig.isGCM and additionalAuthenticatedData ~= nil then
        -- Note - this requires updated version of luaossl that allows setting of additionalAuthenticatedData
        if not SKIP_FEATURE_TEST then 
            if not hasAADSupport() then
                error("CryptoLite.encryptSymmetricEx: AdditionalAuthenticatedData is not supported by this version of luaossl")
            end
        end
        c:encrypt(encKey, ivBytes, true, additionalAuthenticatedData)
    else
        c:encrypt(encKey, ivBytes, true)
    end
    local ciphertext = c:final(plaintext)
    
    local tag = nil
    if (contentEncryptionAlgorithmConfig.isGCM) then
        -- Get from cipher tag for GCM modes
        tag = c:getTag(contentEncryptionAlgorithmConfig.tagLength)
    elseif (contentEncryptionAlgorithmConfig.isAES_CBC_HMAC_SHA2) then
        -- Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.1
        -- compose tag
        local aadBits = 0
        if (additionalAuthenticatedData ~= nil) then
            aadBits = #additionalAuthenticatedData * 8
        end
        -- pack length of AAD in bits into an unsigned 64 bit big-endian integer octet string called AL
        local aadLength = string.pack(">J", aadBits)
        local hashData = 
            (additionalAuthenticatedData ~= nil and additionalAuthenticatedData or "") .. 
            ivBytes ..
            ciphertext ..
            aadLength
        local h = hmac.new(macKey, contentEncryptionAlgorithmConfig.md)
        local signature = h:final(hashData)
        tag = string.sub(signature, 1, contentEncryptionAlgorithmConfig.tagLength)
    else
        -- impossible
        error("CryptoLite.encryptSymmetricEx: contentEncryptionAlgorithm was neither GCM nor AES_CBC_HMAC_SHA2")
    end

    local result = {
        salt = salt,
        iv = ivBytes,
        tag = tag,
        ciphertext = ciphertext
    }

    --logger.debugLog("CryptoLite.encryptSymmetricEx result: " .. logger.dumpAsString(result))
    return result
end

--[[
    Symmetric Decryption using configurable algorithm
    
    This function decrypts ciphertext using symmetric decryption algorithms (AES-GCM or AES-CBC-HMAC-SHA2).
    If the key was derived during encryption (shorter than required), the same salt must be provided.
    
    @param options: Table with the following fields:
        - ciphertext (string, required): The ciphertext to decrypt
        - key (string, required): Decryption key. If less than required key length, will be derived using PBKDF2 with salt
        - iv (string, required): Initialization vector
        - salt (string, optional): Salt used during key derivation. Required if key was derived during encryption
        - tag (string, required): Authentication tag.
        - contentEncryptionAlgorithmConfig (table, required): Config from getContentEncryptionAlgorithmConfig
        - additionalAuthenticatedData (string, optional): Additional authenticated data
    @return plaintext: The decrypted string
--]]
local function decryptSymmetricEx(options)

    local ciphertext = options.ciphertext
    local key = options.key
    local salt = options.salt
    local iv = options.iv
    local tag = options.tag
    local additionalAuthenticatedData = options.additionalAuthenticatedData
    local contentEncryptionAlgorithmConfig = options.contentEncryptionAlgorithmConfig

    if not ciphertext or not key or not iv or not tag or not contentEncryptionAlgorithmConfig then
        error("CryptoLite.decryptSymmetricEx: ciphertext, key, iv, tag and algorithm configuration are required")
    end

    -- If this is a AES_CBC_HMAC_SHA2 cipher, the key length must be correct
    if contentEncryptionAlgorithmConfig.isAES_CBC_HMAC_SHA2 then
        if #key ~= contentEncryptionAlgorithmConfig.keyLength then
            error("CryptoLite.decryptSymmetricEx: key length must be " .. tostring(contentEncryptionAlgorithmConfig.keyLength) .. " for AES_CBC_HMAC_SHA2 cipher")
        end
    end
                
    -- Derive the same key
    local encKey, macKey
    if (contentEncryptionAlgorithmConfig.isGCM) then
        if #key < contentEncryptionAlgorithmConfig.keyLength then
            if not salt then
                error("CryptoLite.decryptSymmetricEx: salt is required based on key length")
            end
            encKey = deriveKey(key, salt, contentEncryptionAlgorithmConfig.keyLength)
        else
            encKey = key:sub(1, contentEncryptionAlgorithmConfig.keyLength)
        end
    elseif (contentEncryptionAlgorithmConfig.isAES_CBC_HMAC_SHA2) then
        -- Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-5.2

        -- macKey is the first half of the key
        local halfLen = math.ceil(#key/2)
        macKey = key:sub(1, halfLen)
        -- encKey is the second half
        encKey = key:sub(halfLen + 1, -1)
    else
        -- impossible
        error("CryptoLite.decryptSymmetricEx: contentEncryptionAlgorithm was neither GCM nor AES_CBC_HMAC_SHA2")
    end

    -- if this is an AES_CBC_HMAC_SHA2 cipher, check integrity and authenticity of aad and ciphertext
    -- otherwise for GCM this will be done by passing the tag and aad to the cipher
    if (contentEncryptionAlgorithmConfig.isAES_CBC_HMAC_SHA2) then
        -- Reference: https://datatracker.ietf.org/doc/html/rfc7518#section-5.2.2.2
        -- compose tag
        local aadBits = 0
        if (additionalAuthenticatedData ~= nil) then
            aadBits = #additionalAuthenticatedData * 8
        end
        -- pack length of AAD in bits into an unsigned 64 bit big-endian integer octet string called AL
        local aadLength = string.pack(">J", aadBits)
        local hashData = 
            (additionalAuthenticatedData ~= nil and additionalAuthenticatedData or "") .. 
            iv ..
            ciphertext ..
            aadLength
        local h = hmac.new(macKey, contentEncryptionAlgorithmConfig.md)
        local signature = h:final(hashData)
        local computedTag = string.sub(signature, 1, contentEncryptionAlgorithmConfig.tagLength)
        if (computedTag ~= tag) then
            error("CryptoLite.decryptSymmetricEx: computed tag ("..logger.dumpAsString(computedTag)..") does not match expected tag ("..logger.dumpAsString(tag)..")")
        end
    end
    
    -- Create cipher
    local c = cipher.new(contentEncryptionAlgorithmConfig.osslName)
    
    -- Decrypt
    if contentEncryptionAlgorithmConfig.isGCM and additionalAuthenticatedData ~= nil then
        if not SKIP_FEATURE_TEST then
            if not hasAADSupport() then
                error("CryptoLite.decryptSymmetricEx: AdditionalAuthenticatedData is not supported by this version of luaossl")
            end
        end
        c:decrypt(encKey, iv, true, additionalAuthenticatedData)
    else
        c:decrypt(encKey, iv, true)
    end
    
    -- Set tag for GCM modes
    if contentEncryptionAlgorithmConfig.isGCM then
        c:setTag(tag)
    end
    
    local plaintext = c:final(ciphertext)

    if ( not plaintext) then
        error("CryptoLite.decryptSymmetricEx: decrytion failed for cipher: " .. contentEncryptionAlgorithmConfig.osslName)
    end

    return plaintext
end

--[[
    ============================================================================
    Asymmetric key ENCRYPTON / DECRYPTION FUNCTIONS (JWT/JWE-compatible)
    ============================================================================
--]]

--[[
    Returns the configuration table for a supported JWE key agreement / key encryption algorithm.
    The configuration describes the algorithm type and any associated parameters (e.g. RSA padding
    mode or KDF to use for ECDH-ES). Raises an error if the algorithm is not supported.
    @param algorithm: The JWE key agreement algorithm identifier string (e.g. "RSA-OAEP", "ECDH-ES", "dir")
    @return: A table containing the algorithm configuration with fields such as:
             - type: algorithm family ("RSA", "ECDH", or "dir")
             - rsaPadding: RSA padding constant (RSA algorithms only)
             - kdf: key derivation function identifier (ECDH algorithms only)
--]]
local function getEncryptionKeyAgreementAlgorithmConfig(algorithm)
    local configs = {
        ["RSA1_5"] = { type = "RSA", rsaPadding = pkey.RSA_PKCS1_PADDING },
        ["RSA-OAEP"] = { type = "RSA", rsaPadding = pkey.RSA_PKCS1_OAEP_PADDING },

        -- This is not supported because luaossl does not yet expose key a means to select
        -- the Main Digest and MGF1 digest (which need to be sha256)
        -- ["RSA-OAEP-256"] = { type = "RSA", rsaPadding = pkey.RSA_PKCS1_OAEP_PADDING },

        -- These are not supported because luaossl does not yet expose key wrapping capabilities
        -- ["A128KW"] = {  },
        -- ["A192KW"] = {  },
        -- ["A256KW"] = {  },
        -- ["A128GCMKW"] = {  },
        -- ["A192GCMKW"] = {  },
        -- ["A256GCMKW"] = {  },

        ["dir"] = { type = "dir" },

        ["ECDH-ES"] = { type = "ECDH", kdf = "concatKDF" }

        -- These are not supported because luaossl does not yet expose key wrapping capabilities
        -- ["ECDH-ES+A128KW"] = { type = "ECDH", kdf = "concatKDF", keyWrapAlg = "A128KW" },
        -- ["ECDH-ES+A192KW"] = { type = "ECDH", kdf = "concatKDF", keyWrapAlg = "A192KW" },
        -- ["ECDH-ES+A256KW"] = { type = "ECDH", kdf = "concatKDF", keyWrapAlg = "A256KW" }
    }
    
    local config = configs[algorithm]
    if not config then
        local keyset = {}
        for k,v in pairs(configs) do
            table.insert(keyset, k)
        end

        error("CryptoLite.getEncryptionKeyAgreementAlgorithmConfig unsupported algorithm: " .. algorithm .. ". Supported alorithms: " .. cjson.encode(keyset))
    end
    
    return config
end

--[[
    Checks whether the given algorithm identifier is a supported JWE key agreement / key encryption algorithm.
    Supported algorithms are: "RSA-OAEP", "dir", "ECDH-ES".
    Unlike getEncryptionKeyAgreementAlgorithmConfig, this function does not raise an error for unsupported algorithms;
    it returns false instead.
    @param algorithm: The key agreement algorithm identifier string to check (e.g. "RSA-OAEP", "ECDH-ES", "dir")
    @return: true if the algorithm is supported, false otherwise
--]]
function CryptoLite.isSupportedEncryptionKeyAgreementAlgorithm(algorithm)
    local success, config = pcall(getEncryptionKeyAgreementAlgorithmConfig, algorithm)
    if (success) then
        return true
    else
        return false
    end
end

--[[
    Determines whether the specified key agreement algorithm uses ECDH (Elliptic Curve Diffie-Hellman).
    @param algorithm: The key agreement algorithm name (e.g. "ECDH-ES", "ECDH-ES+A256KW")
    @return: true if the algorithm is an ECDH-based key agreement algorithm, false otherwise
--]]
function CryptoLite.isECDHEncryptionKeyAgreement(algorithm)
    local result = false
    local success, config = pcall(getEncryptionKeyAgreementAlgorithmConfig, algorithm)
    if (success) then
        result = (config.type == "ECDH")
    else
        result = false
    end
    return result
end

--[[
    Internal function that encrypts plaintext using RSA key agreement combined with a symmetric
    content encryption algorithm. A random Content Encryption Key (CEK) is generated (or supplied),
    the plaintext is encrypted symmetrically with the CEK, and the CEK is then wrapped using RSA
    encryption with the recipient's public key.
    @param options: A table containing:
                    - plaintext (string, required): The plaintext to encrypt
                    - key (string, required): Recipient's RSA public key in PEM format
                    - encryptionKeyAgreementConfig (table, required): Config from getEncryptionKeyAgreementAlgorithmConfig,
                      including rsaPadding
                    - contentEncryptionAlgorithmConfig (table, required): Config from getContentEncryptionAlgorithmConfig
                      including keyLength, ivLength, and jwaName
                    - cek (string, optional): Content Encryption Key bytes; generated randomly if not supplied
                    - iv (string, optional): IV bytes; generated randomly if not supplied
                    - additionalAuthenticatedData (string, optional): AAD for AEAD cipher modes
    @return: A table containing:
             - encryptedKey (string): The RSA-encrypted CEK bytes
             - iv (string): The IV bytes used for symmetric encryption
             - tag (string): The AEAD authentication tag (GCM only)
             - ciphertext (string): The symmetrically encrypted ciphertext bytes
--]]
local function encryptRSAEx(options)
    local plaintext = options.plaintext
    local key = options.key
    local encryptionKeyAgreementConfig = options.encryptionKeyAgreementConfig
    local contentEncryptionAlgorithmConfig = options.contentEncryptionAlgorithmConfig
    
    -- cek may be supplied, but is typically generated
    local cek = options.cek
    if not cek then
        cek = CryptoLite.randomBytes(contentEncryptionAlgorithmConfig.keyLength)
    end

    -- Use provided or generate random IV
    local ivBytes = options.iv or rand.bytes(contentEncryptionAlgorithmConfig.ivLength)

    -- encrypt plaintext with CEK
    local symmetricEncryptionOptions = {
        plaintext = plaintext,
        key = cek,
        contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig,
        iv = ivBytes,
        additionalAuthenticatedData = options.additionalAuthenticatedData
    }
    -- Table with salt, iv, tag (GCM only), ciphertext fields as binary strings
    local symmetricEncryptionResult = encryptSymmetricEx(symmetricEncryptionOptions)

    -- RSA encryption of the cek produces encryptedKey
    local pubKey = pkey.new(key)
    local encryptedKey = pubKey:encrypt(cek, { rsaPadding = encryptionKeyAgreementConfig.rsaPadding })

    -- put it all together (no salt because CEK length doesn't require it)
    local encryptResults = {
        encryptedKey = encryptedKey,
        iv = symmetricEncryptionResult.iv,
        tag = symmetricEncryptionResult.tag,
        ciphertext = symmetricEncryptionResult.ciphertext
    }

    return encryptResults
end

--[[
    Internal function that decrypts ciphertext that was encrypted using RSA key agreement combined
    with a symmetric content encryption algorithm. The encrypted Content Encryption Key (CEK) is
    first unwrapped using RSA decryption with the recipient's private key, then the ciphertext is
    decrypted symmetrically using the recovered CEK.
    @param options: A table containing:
                    - ciphertext (string, required): The symmetrically encrypted ciphertext bytes
                    - key (string, required): Recipient's RSA private key in PEM format
                    - encryptionKeyAgreementConfig (table, required): Config from getEncryptionKeyAgreementAlgorithmConfig,
                      including rsaPadding
                    - contentEncryptionAlgorithmConfig (table, required): Config from getContentEncryptionAlgorithmConfig
                      including jwaName
                    - iv (string, required): The IV bytes used during encryption
                    - tag (string, required): The AEAD authentication tag (GCM only)
                    - encryptedKey (string, required): The RSA-encrypted CEK bytes
                    - additionalAuthenticatedData (string, optional): AAD for AEAD cipher modes
    @return: The decrypted plaintext as a string
--]]
local function decryptRSAEx(options)
    local ciphertext = options.ciphertext
    local key = options.key
    local encryptionKeyAgreementConfig = options.encryptionKeyAgreementConfig
    local contentEncryptionAlgorithmConfig = options.contentEncryptionAlgorithmConfig
    local iv = options.iv
    local tag = options.tag
    local encryptedKey = options.encryptedKey
    local additionalAuthenticatedData = options.additionalAuthenticatedData

    -- Perform RSA decryption on the encryptedKey to get the cek
    local privKey = pkey.new(key)
    local cek = privKey:decrypt(encryptedKey, { rsaPadding = encryptionKeyAgreementConfig.rsaPadding })

    -- Perform symmetric decryption on the ciphertext with the cek to get the plaintext
    local symmetricDecryptionOptions = {
        ciphertext = ciphertext,
        key = cek,
        iv = iv,
        tag = tag,
        contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig,
        additionalAuthenticatedData = additionalAuthenticatedData
    }
    local plaintext = decryptSymmetricEx(symmetricDecryptionOptions)
    return plaintext
end

--[[
    Encrypts plaintext using ECDH key agreement combined with a symmetric content encryption algorithm.
    An ephemeral EC key pair is generated (or supplied via options) and ECDH is performed against the
    recipient's public key to derive a shared secret. The shared secret is processed through the
    configured KDF (none, sha256, or concatKDF) to produce the content encryption key (CEK), which is
    then used to encrypt the plaintext with the specified content encryption algorithm (e.g. A256GCM).
    @param options: A table containing:
                    - plaintext (string, required): The plaintext to encrypt
                    - key (string, required): Recipient's EC public key in PEM format
                    - encryptionKeyAgreementConfig (table, required): Config from getEncryptionKeyAgreementAlgorithmConfig
                    - contentEncryptionAlgorithmConfig (table, required): Config from getContentEncryptionAlgorithmConfig
                    - ephemeralKey (pkey, optional): Ephemeral EC key pair to use; generated if not supplied
                    - iv (string, optional): IV bytes; generated randomly if not supplied
                    - apu (string, optional): Agreement PartyUInfo for concatKDF
                    - apv (string, optional): Agreement PartyVInfo for concatKDF
                    - additionalAuthenticatedData (string, optional): AAD for AEAD cipher modes
    @return: A table containing:
             - ephemeralKeyPublicPEM (string): The ephemeral public key in PEM format
             - iv (string): The IV bytes used
             - tag (string): The AEAD authentication tag
             - ciphertext (string): The encrypted ciphertext bytes
             - encryptedKey (string or nil): The wrapped CEK (nil when using direct key agreement)
--]]
local function encryptECDHEx(options)
    local plaintext = options.plaintext
    local key = options.key
    local encryptionKeyAgreementConfig = options.encryptionKeyAgreementConfig
    local contentEncryptionAlgorithmConfig = options.contentEncryptionAlgorithmConfig

    if not plaintext or not key then
        error("CryptoLite.encryptECDHEx: plaintext and key are required")
    end

    -- one of "none" (uses shared secret as the cek), "sha256", or "concatKDF"
    local kdf = encryptionKeyAgreementConfig.kdf or "sha256"
    
    -- Load recipient's public key
    local recipientPubKey = pkey.new(key)
    
    -- Either use the ephemeral public key passed as an option or generate a new one
    local ephemeralKey = options.ephemeralKey
    if not ephemeralKey then
        -- Get the curve name from the recipient's key
        local curveInfo = CryptoLite.determineECKeyProperties(key)
        
        -- Generate ephemeral key pair on the same curve
        local genParams = {
            type = "EC",
            curve = curveInfo.curveName
        }

        ephemeralKey = pkey.new(genParams)
    end
    
    -- Perform ECDH to derive shared secret

    -- Compute sharedSecret, Z
    -- this requires updated version of luaossl that contains https://github.com/wahern/luaossl/pull/214
    if not SKIP_FEATURE_TEST then
        if not hasECDeriveSupport() then
            error("CryptoLite.encryptECDHEx: ECDH key derivation is not supported by this version of luaossl")
        end
    end
    local sharedSecret = ephemeralKey:derive(recipientPubKey)

    local cek = nil
    local encryptedKey = nil

    if (kdf == "none") then
        cek = sharedSecret
        --logger.debugLog("CryptoLite.encryptECDHEx using sharedSecret as cek: " .. logger.dumpAsString(cek))
    elseif (kdf == "sha256") then
        -- Derive content encryption key from shared secret using SHA-256
        local md = digest.new("sha256")
        cek = md:final(sharedSecret)
        --logger.debugLog("CryptoLite.encryptECDHEx using sha256(sharedSecret) as cek: " .. logger.dumpAsString(cek))
    elseif (kdf == "concatKDF") then
        -- derive shared key via concatKDF
        local sharedKey = CryptoLite.concatKDF({
            sharedSecret = sharedSecret,
            keyDataLen = (contentEncryptionAlgorithmConfig.keyLength * 8), -- in bits
            algorithm = contentEncryptionAlgorithmConfig.jwaName,
            apu = options.apu,
            apv = options.apv
        })

        -- If AES key wrapping is being used instead of direct, then generate a new cek now
        -- and wrap with the sharedKey
        -- and then create an encryptedKey which is the cek encrypted with the current cek
        -- and the encrypted cek (I believe) would need to be returned in result.cek 
        if (encryptionKeyAgreementConfig.keyWrapAlg ~= nil) then
            -- generate a random cek, and wrap with sharedKey to produce encyptedKey
            --cek = CryptoLite.randomBytes(contentEncryptionAlgorithmConfig.keyLength)
            
            -- TODO - figure out if luaossl can be extended to support AES Key Wrapping
            error("CryptoLite.encryptECDHEx: key wrapping not yet supported")

        else
            -- Direct mode is being used, the sharedKey is the cek
            cek = sharedKey
            encryptedKey = nil
        end

        --logger.debugLog("CryptoLite.encryptECDHEx using concatKDF(sharedSecret) as cek: " .. logger.dumpAsString(cek))
    else
        -- invalid kdf
        logger.debugLog("CryptoLite.encryptECDHEx invalid kdf supplied: " .. kdf)
        error("CryptoLite.encryptECDHEx: invalid kdf supplied: " .. kdf)
    end

    -- Use provided or generate random IV
    local ivBytes = options.iv or rand.bytes(contentEncryptionAlgorithmConfig.ivLength)
    

    -- symmetric encryption of plaintext is done with the cek now
    local symmetricEncryptionOptions = {
        plaintext = plaintext,
        key = cek,
        contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig,
        iv = ivBytes,
        additionalAuthenticatedData = options.additionalAuthenticatedData
    }
    -- Table with salt, iv, tag (GCM only), ciphertext fields as binary strings
    local symmetricEncryptionResult = encryptSymmetricEx(symmetricEncryptionOptions)

    -- Compose the results, which are the results of the symmetric encryption
    -- plus the ephemeral public key
    local result = {
        ephemeralKeyPublicPEM = ephemeralKey:toPEM("public"),
        iv = symmetricEncryptionResult.iv,
        tag = symmetricEncryptionResult.tag,
        ciphertext = symmetricEncryptionResult.ciphertext,
    }
    
    return result
end

--[[
    Decrypts ciphertext using ECDH key agreement combined with a symmetric content encryption algorithm.
    ECDH is performed between the recipient's private key and the sender's ephemeral public key to
    derive the shared secret. The shared secret is processed through the configured KDF (none, sha256,
    or concatKDF) to recover the content encryption key (CEK), which is then used to decrypt the
    ciphertext with the specified content encryption algorithm (e.g. A256GCM).
    @param options: A table containing:
                    - ciphertext (string, required): The ciphertext bytes to decrypt
                    - key (string, required): Recipient's EC private key in PEM format
                    - ephemeralKeyPublicPEM (string, required): Sender's ephemeral EC public key in PEM format
                    - tag (string, required): The AEAD authentication tag
                    - iv (string, required): The IV bytes used during encryption
                    - encryptionKeyAgreementConfig (table, required): Config from getEncryptionKeyAgreementAlgorithmConfig
                    - contentEncryptionAlgorithmConfig (table, required): Config from getContentEncryptionAlgorithmConfig
                    - apu (string, optional): Agreement PartyUInfo for concatKDF
                    - apv (string, optional): Agreement PartyVInfo for concatKDF
                    - encryptedKey (string, optional): Wrapped CEK (required when key wrapping is used)
                    - additionalAuthenticatedData (string, optional): AAD for AEAD cipher modes
    @return: The decrypted plaintext byte string
--]]
local function decryptECDHEx(options)
    local ciphertext = options.ciphertext
    local privateKeyPEM = options.key
    local ephemeralKeyPublicPEM = options.ephemeralKeyPublicPEM
    local tag = options.tag
    local iv = options.iv
    local encryptionKeyAgreementConfig = options.encryptionKeyAgreementConfig
    local contentEncryptionAlgorithmConfig = options.contentEncryptionAlgorithmConfig

    local kdf = encryptionKeyAgreementConfig.kdf

    if not ciphertext or not privateKeyPEM or not ephemeralKeyPublicPEM or not tag or not iv or not kdf or not encryptionKeyAgreementConfig or not contentEncryptionAlgorithmConfig then
        error("CryptoLite.decryptECDHEx: missing decryption options")
    end

    -- Load private key and ephemeral public key
    local recipientPrivateKey = pkey.new(privateKeyPEM)

    local curveInfo = CryptoLite.determineECKeyProperties(ephemeralKeyPublicPEM)
    local ephemeralPublicKey = pkey.new(ephemeralKeyPublicPEM)
    -- trying this
    --local ephemeralPublicKey = pkey.new(ephemeralKeyPublicPEM, "pem", "public", curveInfo.curveName)
    
    -- Perform ECDH to derive shared secret
    -- this requires updated version of luaossl that contains https://github.com/wahern/luaossl/pull/214
    if not SKIP_FEATURE_TEST then
        if not hasECDeriveSupport() then
            error("CryptoLite.decryptECDHEx: ECDH key derivation is not supported by this version of luaossl")
        end
    end
    local sharedSecret = recipientPrivateKey:derive(ephemeralPublicKey)
    
    local cek = nil
    if (kdf == "none") then
        cek = sharedSecret
        --logger.debugLog("CryptoLite.decryptECDHEx using sharedSecret as cek: " .. logger.dumpAsString(cek))
    elseif (kdf == "sha256") then
        -- Derive content encryption key from shared secret using SHA-256
        local md = digest.new("sha256")
        cek = md:final(sharedSecret)
        --logger.debugLog("CryptoLite.decryptECDHEx using sha256(sharedSecret) as cek: " .. logger.dumpAsString(cek))
    elseif (kdf == "concatKDF") then
        local sharedKey = CryptoLite.concatKDF({
            sharedSecret = sharedSecret,
            keyDataLen = (contentEncryptionAlgorithmConfig.keyLength * 8), -- in bits
            algorithm = contentEncryptionAlgorithmConfig.jwaName,
            apu = options.apu,
            apv = options.apv
        })

        -- If AES key wrapping is being used instead of direct, then unwrap options.encryptedKey using sharedKey to get the cek
        if (encryptionKeyAgreementConfig.keyWrapAlg ~= nil) then
            -- TODO - figure out if luaossl can be extended to support AES Key Wrapping
            if not options.encryptedKey then
                error("CryptoLite.decryptECDHEx: encryption key agreement uses key wrapping and no encryptedKey supplied")
            end
            -- for now, always error as we do not support this until key wrapping is available in luaossl
            error("CryptoLite.decryptECDHEx: key wrapping not yet supported")
        else
            -- Direct mode is being used, the sharedKey is the cek
            cek = sharedKey
        end
    else
        -- invalid kdf
        error("CryptoLite.decryptECDHEx: invalid kdf supplied: " .. kdf)
    end

    -- perform symmetric decryption of the ciphertext with the cek
    local symmetricDecryptionOptions = {
        ciphertext = ciphertext,
        key = cek,
        iv = iv,
        tag = tag,
        contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig,
        additionalAuthenticatedData = options.additionalAuthenticatedData
    }
    local plaintext = decryptSymmetricEx(symmetricDecryptionOptions)
    return plaintext
end

--[[
    ============================================================================
    Publicly exposed ENCRYPTON / DECRYPTION FUNCTIONS
    ============================================================================
--]]


--[[
    Encrypts plaintext using the specified JWE-compatible key agreement and content encryption algorithms.
    Dispatches to the appropriate internal encryption function (RSA, ECDH, or symmetric direct) based on
    the encryptionKeyAgreement algorithm identifier.
    @param options: A table containing:
                    - plaintext (string, required): The plaintext to encrypt
                    - key (string, required): The encryption key or public key in PEM format
                    - encryptionKeyAgreement (string, required): JWE key agreement algorithm (e.g. "RSA-OAEP", "ECDH-ES", "dir")
                    - contentEncryptionAlgorithm (string, optional): JWE content encryption algorithm (e.g. "A256GCM");
                    - iv (string, optional): IV bytes; generated randomly if not supplied
                    - apu (string, optional): Agreement PartyUInfo (ECDH-ES only)
                    - apv (string, optional): Agreement PartyVInfo (ECDH-ES only)
                    - ephemeralKey (pkey, optional): Ephemeral EC key pair (ECDH-ES only)
                    - additionalAuthenticatedData (string, optional): AAD for AEAD cipher modes
    @return: For RSA: a table with iv, tag, ciphertext, and encryptedKey fields.
             For ECDH-ES: a table with ephemeralKeyPublicPEM, iv, tag, ciphertext, and encryptedKey fields.
             For dir: a table with iv, tag, ciphertext, and salt fields.
--]]
function CryptoLite.encrypt(options)
    local plaintext = options.plaintext
    local key = options.key
    local encryptionKeyAgreement = options.encryptionKeyAgreement
    local contentEncryptionAlgorithm = options.contentEncryptionAlgorithm

    if not plaintext or not key or not encryptionKeyAgreement then
        error("CryptoLite.encrypt: plaintext, key, encryptionKeyAgreement are required")
    end

    local encryptionKeyAgreementConfig = getEncryptionKeyAgreementAlgorithmConfig(encryptionKeyAgreement)
    if not encryptionKeyAgreementConfig then
        error("CryptoLite.encrypt unrecognized encryptionKeyAgreement: " .. encryptionKeyAgreement)
    end

    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)
    if not contentEncryptionAlgorithmConfig then
        error("CryptoLite.encrypt unrecognized contentEncryptionAlgorithm: " .. contentEncryptionAlgorithm)
    end

    if encryptionKeyAgreementConfig.type == "RSA" then
        local encryptOptions = {
            plaintext = plaintext,
            key = key,
            encryptionKeyAgreementConfig = encryptionKeyAgreementConfig,
            contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig
        }
        if options.iv then
            encryptOptions.iv = options.iv
        end
        if options.additionalAuthenticatedData then
            encryptOptions.additionalAuthenticatedData = options.additionalAuthenticatedData
        end

        return encryptRSAEx(encryptOptions)
    elseif encryptionKeyAgreementConfig.type == "ECDH" then
        local encryptOptions = {
            plaintext = plaintext,
            key = key,
            encryptionKeyAgreementConfig = encryptionKeyAgreementConfig,
            contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig
        }
        if options.iv then
            encryptOptions.iv = options.iv
        end
        if options.apu then
            encryptOptions.apu = options.apu
        end
        if options.apv then
            encryptOptions.apu = options.apv
        end
        if options.ephemeralKey then
            encryptOptions.ephemeralKey = options.ephemeralKey
        end
        if options.additionalAuthenticatedData then
            encryptOptions.additionalAuthenticatedData = options.additionalAuthenticatedData
        end
        return encryptECDHEx(encryptOptions)
    elseif encryptionKeyAgreementConfig.type == "dir" then
        -- plaintext (string, required): The string to encrypt
        -- key (string, required): Encryption key. If less than required key length, will be derived using PBKDF2 with salt
        -- algorithm (string, optional): Algorithm to use: A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, A256CBC-HS512
        -- iv (string, optional): IV bytes. Will be generated if not supplied
        -- additionalAuthenticatedData (string, optional): AAD for GCM modes
        local encryptOptions = {
            plaintext = options.plaintext,
            key = options.key,
            contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig
        }
        if options.iv then
            encryptOptions.iv = options.iv
        end
        if options.additionalAuthenticatedData then
            encryptOptions.additionalAuthenticatedData = options.additionalAuthenticatedData
        end

        return encryptSymmetricEx(encryptOptions)
    else
        error("CryptoLite.encrypt unrecognized encryptionKeyAgreement type: " .. encryptionKeyAgreementConfig.type)
    end
end

--[[
    Decrypts ciphertext using the specified JWE-compatible key agreement and content encryption algorithms.
    Dispatches to the appropriate internal decryption function (RSA, ECDH, or symmetric direct) based on
    the encryptionKeyAgreement algorithm identifier.
    @param options: A table containing:
                    - ciphertext (string, required): The ciphertext to decrypt
                    - key (string, required): The decryption key or private key in PEM format
                    - encryptionKeyAgreement (string, required): JWE key agreement algorithm (e.g. "RSA-OAEP", "ECDH-ES", "dir")
                    - contentEncryptionAlgorithm (string, optional): JWE content encryption algorithm (e.g. "A256GCM");
                                                                      required for non-RSA algorithms
                    - iv (string, optional): IV bytes used during encryption
                    - tag (string, optional): AEAD authentication tag (ECDH-ES and dir GCM modes)
                    - ephemeralKeyPublicPEM (string, optional): Sender's ephemeral EC public key in PEM format (ECDH-ES only)
                    - apu (string, optional): Agreement PartyUInfo (ECDH-ES only)
                    - apv (string, optional): Agreement PartyVInfo (ECDH-ES only)
                    - encryptedKey (string, optional): Wrapped CEK (ECDH-ES with key wrapping only)
                    - salt (string, optional): PBKDF2 salt used during encryption (dir mode only)
                    - additionalAuthenticatedData (string, optional): AAD for AEAD cipher modes
    @return: The decrypted plaintext byte string
--]]
function CryptoLite.decrypt(options)
    local ciphertext = options.ciphertext
    local key = options.key
    local encryptionKeyAgreement = options.encryptionKeyAgreement
    local contentEncryptionAlgorithm = options.contentEncryptionAlgorithm

    if not ciphertext or not key or not encryptionKeyAgreement then
        error("CryptoLite.decrypt: ciphertext, key, encryptionKeyAgreement are required")
    end

    local encryptionKeyAgreementConfig = getEncryptionKeyAgreementAlgorithmConfig(encryptionKeyAgreement)
    if not encryptionKeyAgreementConfig then
        error("CryptoLite.decrypt unrecognized encryptionKeyAgreement: " .. encryptionKeyAgreement)
    end

    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)
    if not contentEncryptionAlgorithmConfig then
        error("CryptoLite.encrypt unrecognized contentEncryptionAlgorithm: " .. contentEncryptionAlgorithm)
    end

    if encryptionKeyAgreementConfig.type == "RSA" then
        local decryptOptions = {
            ciphertext = ciphertext,
            key = key,
            encryptionKeyAgreementConfig = encryptionKeyAgreementConfig,
            contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig
        }
        if options.encryptedKey then
            decryptOptions.encryptedKey = options.encryptedKey
        end
        if options.iv then
            decryptOptions.iv = options.iv
        end
        if options.tag then
            decryptOptions.tag = options.tag
        end
        if options.additionalAuthenticatedData then
            decryptOptions.additionalAuthenticatedData = options.additionalAuthenticatedData
        end

        return decryptRSAEx(decryptOptions)
    elseif encryptionKeyAgreementConfig.type == "ECDH" then
        local decryptOptions = {
            ciphertext = ciphertext,
            key = key,
            encryptionKeyAgreementConfig = encryptionKeyAgreementConfig,
            contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig
        }
        if options.ephemeralKeyPublicPEM then
            decryptOptions.ephemeralKeyPublicPEM = options.ephemeralKeyPublicPEM
        end
        if options.iv then
            decryptOptions.iv = options.iv
        end
        if options.tag then
            decryptOptions.tag = options.tag
        end
        if options.apu then
            decryptOptions.apu = options.apu
        end
        if options.apv then
            decryptOptions.apu = options.apv
        end
        if options.additionalAuthenticatedData then
            decryptOptions.additionalAuthenticatedData = options.additionalAuthenticatedData
        end
        return decryptECDHEx(decryptOptions)
    elseif encryptionKeyAgreementConfig.type == "dir" then
        local decryptOptions = {
            ciphertext = ciphertext,
            key = key,
            iv = options.iv,
            contentEncryptionAlgorithmConfig = contentEncryptionAlgorithmConfig
        }
        if options.salt then
            decryptOptions.salt = options.salt
        end
        if options.tag then
            decryptOptions.tag = options.tag
        end
        if options.additionalAuthenticatedData then
            decryptOptions.additionalAuthenticatedData = options.additionalAuthenticatedData
        end

        return decryptSymmetricEx(decryptOptions)
    else
        error("CryptoLite.decrypt unrecognized encryptionKeyAgreement type: " .. encryptionKeyAgreementConfig.type)
    end
end

--[[
    Symmetric Encryption using A256GCM (default)
    @param plaintext: The string to encrypt
    @param key: Encryption key (string). If less than 32 bytes, will be derived using PBKDF2 with salt
    @return encrypted: Base64URL-encoded encrypted data with format: salt:iv:tag:ciphertext (for GCM) or salt:iv:ciphertext (for CBC)
--]]
function CryptoLite.encryptSymmetric(plaintext, key)
    local contentEncryptionAlgorithm = "A256GCM"
    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)

    local encryptOptions = {
        plaintext = plaintext,
        key = key,
        encryptionKeyAgreement = "dir",
        contentEncryptionAlgorithm = contentEncryptionAlgorithm
    }
    local encryptResults = CryptoLite.encrypt(encryptOptions)

    local salt = encryptResults.salt
    local iv = encryptResults.iv
    local tag = encryptResults.tag
    local ciphertext = encryptResults.ciphertext

    -- Combine salt:iv:tag:ciphertext (for GCM) or salt:iv:ciphertext (for CBC)
    local combined
    if contentEncryptionAlgorithmConfig.isGCM then
        combined = salt .. iv .. tag .. ciphertext
    else
        combined = salt .. iv .. ciphertext
    end
    return CryptoLite.base64URLEncode(combined)
end

--[[
    Symmetric Decryption using A256GCM (default)
    @param encrypted: Base64URL-encoded encrypted data from encryptSymmetric
    @param key: Decryption key (same as used for encryption)
    @return plaintext: The decrypted string
--]]
function CryptoLite.decryptSymmetric(encrypted, key)
    if not encrypted or not key then
        error("CryptoLite.decryptSymmetric: encrypted data and key are required")
    end
    
    -- Decode from base64
    local combined = CryptoLite.base64URLDecode(encrypted)

    local encryptionKeyAgreement = "dir"
    local contentEncryptionAlgorithm = "A256GCM"
    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)

    -- Extract components safely
    local currentIndex = 1
    if (currentIndex + (SALT_LENGTH-1) > #combined) then
        error("Combined length is too short to contain salt")
    end
    local salt = combined:sub(currentIndex, currentIndex+SALT_LENGTH-1)
    currentIndex = currentIndex+SALT_LENGTH

    if (currentIndex + (contentEncryptionAlgorithmConfig.ivLength-1) > #combined) then
        error("Combined length is too short to contain iv")
    end
    local iv = combined:sub(currentIndex, currentIndex+contentEncryptionAlgorithmConfig.ivLength-1)
    currentIndex = currentIndex+contentEncryptionAlgorithmConfig.ivLength

    local tag = nil
    if contentEncryptionAlgorithmConfig.isGCM then
        if (currentIndex + (contentEncryptionAlgorithmConfig.tagLength-1) > #combined) then
            error("Combined length is too short to contain iv")
        end
        tag = combined:sub(currentIndex, currentIndex+contentEncryptionAlgorithmConfig.tagLength-1)
        currentIndex = currentIndex+contentEncryptionAlgorithmConfig.tagLength
    end
    if (currentIndex > #combined) then
        error("Combined length is too short to contain ciphertext")
    end
    local ciphertext = combined:sub(currentIndex)

    local decryptOptions = {
        ciphertext = ciphertext,
        key = key,
        salt = salt,
        iv = iv,
        tag = tag,
        encryptionKeyAgreement = encryptionKeyAgreement,
        contentEncryptionAlgorithm = contentEncryptionAlgorithm
    }

    return CryptoLite.decrypt(decryptOptions)
end

--[[
    RSA Encryption with RSA-OAEP key agreement and A256GCM content encryption.
    @param plaintext: The string to encrypt
    @param publicKeyPEM: RSA public key in PEM format
    @return encrypted: Base64URL-encoded encrypted data
--]]
function CryptoLite.encryptRSA(plaintext, publicKeyPEM)
    local encryptionKeyAgreement = "RSA-OAEP"
    local contentEncryptionAlgorithm = "A256GCM"

    local encryptResults = CryptoLite.encrypt({
        plaintext = plaintext,
        key = publicKeyPEM,
        encryptionKeyAgreement = encryptionKeyAgreement,
        contentEncryptionAlgorithm = contentEncryptionAlgorithm
    })

    -- Store length to help with parsing
    local encryptedKeyLen = string.pack(">I4", #encryptResults.encryptedKey)

    -- Combine encryptedKeyLen:encryptedKey:iv:tag:ciphertext (no tag for CBC ciphers)
    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)
    local combined
    if contentEncryptionAlgorithmConfig.isGCM then
        combined = encryptedKeyLen .. encryptResults.encryptedKey .. encryptResults.iv .. encryptResults.tag .. encryptResults.ciphertext
    else
        combined = encryptedKeyLen .. encryptResults.encryptedKey .. encryptResults.iv .. encryptResults.ciphertext
    end

    return CryptoLite.base64URLEncode(combined)
end

--[[
    RSA Decryption with RSA-OAEP key agreement and A256GCM content encryption.
    @param encrypted: Base64URL-encoded encrypted data from encryptRSA
    @param privateKeyPEM: RSA private key in PEM format
    @return plaintext: The decrypted string
--]]
function CryptoLite.decryptRSA(encrypted, privateKeyPEM)
    -- Decode from base64url
    local combined = CryptoLite.base64URLDecode(encrypted)

    local encryptionKeyAgreement = "RSA-OAEP"
    local contentEncryptionAlgorithm = "A256GCM"
    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)

    -- Extract components safely
    currentIndex = 1
    if (currentIndex + 4 > #combined) then
        error("Combined length is too short to contain encrypted key length")
    end
    local encryptedKeyLen = string.unpack(">I4", combined:sub(currentIndex, 4))
    local currentIndex = currentIndex + 4

    if (currentIndex + (encryptedKeyLen-1) > #combined) then
        error("Combined length is too short to contain encryptedKey")
    end
    local encryptedKey = combined:sub(currentIndex, currentIndex + encryptedKeyLen-1)
    currentIndex = currentIndex + encryptedKeyLen

    if (currentIndex + (contentEncryptionAlgorithmConfig.ivLength-1) > #combined) then
        error("Combined length is too short to contain iv")
    end
    local iv = combined:sub(currentIndex, currentIndex+contentEncryptionAlgorithmConfig.ivLength-1)
    currentIndex = currentIndex + contentEncryptionAlgorithmConfig.ivLength

    local tag = nil
    if contentEncryptionAlgorithmConfig.isGCM then
        if (currentIndex + (contentEncryptionAlgorithmConfig.tagLength-1) > #combined) then
            error("Combined length is too short to contain iv")
        end
        tag = combined:sub(currentIndex, currentIndex + contentEncryptionAlgorithmConfig.tagLength-1)
        currentIndex = currentIndex + contentEncryptionAlgorithmConfig.tagLength
    end
    if (currentIndex > #combined) then
        error("Combined length is too short to contain ciphertext")
    end
    local ciphertext = combined:sub(currentIndex)

    local result = CryptoLite.decrypt({
        ciphertext = ciphertext,
        key = privateKeyPEM,
        encryptionKeyAgreement = encryptionKeyAgreement,
        contentEncryptionAlgorithm = contentEncryptionAlgorithm,
        encryptedKey = encryptedKey,
        iv = iv,
        tag = tag
    })
    return result
end

--[[
    Encrypts plaintext using raw RSA with OAEP padding with the provided public key.
    This is a low-level function that performs a single RSA encryption operation without any
    envelope or encoding.
    @param plaintext: The plaintext as a binary string
    @param publicKeyPEM: RSA public key in PEM format
    @param rsaPaddingStr: The RSA padding algorithm to use. Should be one of: "RSA_PKCS1_PADDING", "RSA_PKCS1_OAEP_PADDING"
    @return: The raw RSA-encrypted ciphertext bytes (binary string)
--]]
function CryptoLite.encryptRSARaw(plaintext, publicKeyPEM, rsaPaddingStr)

    if not plaintext or not publicKeyPEM or not rsaPaddingStr then
        error("CryptoLite.encryptRSARaw: plaintext, publicKeyPEM and rsaPaddingStr are required")
    end

    -- Load private key
    local pubKey = pkey.new(publicKeyPEM)
    
    -- RSA encryption
    local ciphertext = pubKey:encrypt(plaintext, { rsaPadding = getRSAPadding(rsaPaddingStr) })
    
    return ciphertext    
end


--[[
    Decrypts raw RSA-encrypted ciphertext using OAEP padding with the provided private key.
    This is a low-level function that performs a single RSA decryption operation without any
    envelope or encoding — the ciphertext must be raw RSA-encrypted bytes.
    @param ciphertext: The raw RSA-encrypted ciphertext bytes (binary string)
    @param privateKeyPEM: RSA private key in PEM format
    @param rsaPaddingStr: The RSA padding algorithm to use. Should be one of: "RSA_PKCS1_PADDING", "RSA_PKCS1_OAEP_PADDING"
    @return: The decrypted plaintext as a binary string
--]]
function CryptoLite.decryptRSARaw(ciphertext, privateKeyPEM, rsaPaddingStr)
    if not ciphertext or not privateKeyPEM or not rsaPaddingStr then
        error("CryptoLite.decryptRSARaw: ciphertext, privateKeyPEM and rsaPaddingStr are required")
    end

    -- Load private key
    local privKey = pkey.new(privateKeyPEM)
    
    -- RSA decryption
    local plaintext = privKey:decrypt(ciphertext, { rsaPadding = getRSAPadding(rsaPaddingStr) })
    
    return plaintext    
end


--[[
    ECDSA Hybrid Encryption (ECDH key exchange + AES-256-GCM)
    Uses Elliptic Curve Diffie-Hellman for key exchange, then symmetric encryption
    @param plaintext: The string to encrypt
    @param publicKeyPEM: EC public key in PEM format
    @return encrypted: Base64URL-encoded encrypted data with format: ephemeralPubKey:iv:tag:ciphertext
    -- Not available until the luaossl in IVIA contains https://github.com/wahern/luaossl/pull/214
--]]
function CryptoLite.encryptECDSA(plaintext, publicKeyPEM)
    
    local encryptionKeyAgreement = "ECDH-ES"
    local contentEncryptionAlgorithm = "A256GCM"

    local encryptResults = CryptoLite.encrypt({
        plaintext = plaintext,
        key = publicKeyPEM,
        encryptionKeyAgreement = encryptionKeyAgreement,
        contentEncryptionAlgorithm = contentEncryptionAlgorithm
    })

    -- Combine ephemeralPubKey:iv:tag:ciphertext
    -- Store lengths to help with parsing
    local ephemeralKeyPublicPEMLen = string.pack(">I4", #encryptResults.ephemeralKeyPublicPEM)

    -- Combine encryptedKeyLen:encryptedKey:iv:tag:ciphertext (no tag for CBC ciphers)
    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)
    local combined
    if contentEncryptionAlgorithmConfig.isGCM then
        combined = ephemeralKeyPublicPEMLen .. encryptResults.ephemeralKeyPublicPEM .. encryptResults.iv .. encryptResults.tag .. encryptResults.ciphertext
    else
        combined = ephemeralKeyPublicPEMLen .. encryptResults.ephemeralKeyPublicPEM .. encryptResults.iv .. encryptResults.ciphertext
    end
    
    return CryptoLite.base64URLEncode(combined)
end

--[[
    ECDSA Hybrid Decryption
    @param encrypted: Base64URL-encoded encrypted data from encryptECDSA
    @param privateKeyPEM: EC private key in PEM format
    @return plaintext: The decrypted string
    -- Not available until the luaossl in IVIA contains https://github.com/wahern/luaossl/pull/214
--]]
function CryptoLite.decryptECDSA(encrypted, privateKeyPEM)

    if not encrypted or not privateKeyPEM then
        error("CryptoLite.decryptECDSA: encrypted data and privateKeyPEM are required")
    end

    -- Decode from base64url
    local combined = CryptoLite.base64URLDecode(encrypted)

    local encryptionKeyAgreement = "ECDH-ES"
    local contentEncryptionAlgorithm = "A256GCM"

    local contentEncryptionAlgorithmConfig = getContentEncryptionAlgorithmConfig(contentEncryptionAlgorithm)

    -- Extract components safely
    currentIndex = 1
    if (currentIndex + 4 > #combined) then
        error("Combined length is too short to contain ephemeralKeyPublicPEMLen")
    end
    local ephemeralKeyPublicPEMLen = string.unpack(">I4", combined:sub(1, 4))
    currentIndex = currentIndex + 4

    if (currentIndex + (ephemeralKeyPublicPEMLen-1) > #combined) then
        error("Combined length is too short to contain ephemeralKeyPublicPEM")
    end
    local ephemeralKeyPublicPEM = combined:sub(currentIndex, currentIndex + ephemeralKeyPublicPEMLen-1)
    currentIndex = currentIndex + ephemeralKeyPublicPEMLen

    if (currentIndex + (contentEncryptionAlgorithmConfig.ivLength-1) > #combined) then
        error("Combined length is too short to contain iv")
    end
    local iv = combined:sub(currentIndex, currentIndex+contentEncryptionAlgorithmConfig.ivLength-1)
    currentIndex = currentIndex + contentEncryptionAlgorithmConfig.ivLength

    local tag = nil
    if contentEncryptionAlgorithmConfig.isGCM then
        if (currentIndex + (contentEncryptionAlgorithmConfig.tagLength-1) > #combined) then
            error("Combined length is too short to contain iv")
        end
        tag = combined:sub(currentIndex, currentIndex + contentEncryptionAlgorithmConfig.tagLength-1)
        currentIndex = currentIndex + contentEncryptionAlgorithmConfig.tagLength
    end

    if (currentIndex > #combined) then
        error("Combined length is too short to contain ciphertext")
    end
    local ciphertext = combined:sub(currentIndex)

    return CryptoLite.decrypt({
        ciphertext = ciphertext,
        key = privateKeyPEM,
        ephemeralKeyPublicPEM = ephemeralKeyPublicPEM,
        iv = iv,
        tag = tag,
        encryptionKeyAgreement = encryptionKeyAgreement,
        contentEncryptionAlgorithm = contentEncryptionAlgorithm
    })
end

--[[
    ============================================================================
    Key format conversion functions
    ============================================================================
--]]

--[[
    Convert RSA JWK to PEM format
    @param jwk: RSA JWK object
    @return PEM: RSA key in PEM format, or nil and error message
--]]
local function jwkRSAToPEM(jwk)
    -- Check for required public key components
    if not jwk.n or not jwk.e then
        error("CryptoLite.jwkRSAToPEM: RSA JWK requires 'n' and 'e' parameters")
    end
    
    -- Decode base64url components
    local n = CryptoLite.base64URLDecode(jwk.n)
    local e = CryptoLite.base64URLDecode(jwk.e)
    
    -- Check if this is a private key
    local isPrivate = jwk.d ~= nil
    
    if isPrivate then
        -- Private key requires d, p, q, dp, dq, qi
        if not jwk.d or not jwk.p or not jwk.q then
            error("CryptoLite.jwkRSAToPEM: RSA private key JWK requires 'd', 'p', and 'q' parameters")
        end
        
        local d = CryptoLite.base64URLDecode(jwk.d)
        local p = CryptoLite.base64URLDecode(jwk.p)
        local q = CryptoLite.base64URLDecode(jwk.q)
        
        -- Optional CRT parameters (if not provided, they can be computed)
        local dp = jwk.dp and CryptoLite.base64URLDecode(jwk.dp) or nil
        local dq = jwk.dq and CryptoLite.base64URLDecode(jwk.dq) or nil
        local qi = jwk.qi and CryptoLite.base64URLDecode(jwk.qi) or nil
        
        -- Build RSA private key ASN.1 structure
        -- RSAPrivateKey ::= SEQUENCE {
        --   version           Version (0),
        --   modulus           INTEGER,  -- n
        --   publicExponent    INTEGER,  -- e
        --   privateExponent   INTEGER,  -- d
        --   prime1            INTEGER,  -- p
        --   prime2            INTEGER,  -- q
        --   exponent1         INTEGER,  -- dp (d mod (p-1))
        --   exponent2         INTEGER,  -- dq (d mod (q-1))
        --   coefficient       INTEGER   -- qi (q^-1 mod p)
        -- }
        
        local version = "\x00"  -- Version 0
        
        -- Encode each component as ASN.1 INTEGER
        local versionBer = ber.encode({ type = ber.Types.INTEGER, data = version })
        local nBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(n) })
        local eBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(e) })
        local dBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(d) })
        local pBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(p) })
        local qBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(q) })
        
        -- If CRT parameters not provided, use zero placeholders
        -- (OpenSSL can compute them)
        local dpBer = dp and ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(dp) })
                         or ber.encode({ type = ber.Types.INTEGER, data = "\x00" })
        local dqBer = dq and ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(dq) })
                         or ber.encode({ type = ber.Types.INTEGER, data = "\x00" })
        local qiBer = qi and ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(qi) })
                         or ber.encode({ type = ber.Types.INTEGER, data = "\x00" })
        
        -- Combine into SEQUENCE
        local sequence = versionBer .. nBer .. eBer .. dBer .. pBer .. qBer .. dpBer .. dqBer .. qiBer
        local privateKeyBer = ber.encode({ type = ber.Types.SEQUENCE, data = sequence })
        
        -- Base64 encode and format as PEM
        local privateKeyB64 = CryptoLite.base64Encode(privateKeyBer)
        local pem = "-----BEGIN RSA PRIVATE KEY-----\n"
        
        -- Split into 64-character lines
        for i = 1, #privateKeyB64, 64 do
            pem = pem .. privateKeyB64:sub(i, i + 63) .. "\n"
        end
        
        pem = pem .. "-----END RSA PRIVATE KEY-----"
        return pem
        
    else
        -- Public key
        -- RSAPublicKey ::= SEQUENCE {
        --   modulus           INTEGER,  -- n
        --   publicExponent    INTEGER   -- e
        -- }
        
        local nBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(n) })
        local eBer = ber.encode({ type = ber.Types.INTEGER, data = padIfSigned(e) })
        
        local sequence = nBer .. eBer
        local publicKeyBer = ber.encode({ type = ber.Types.SEQUENCE, data = sequence })
        
        -- Wrap in SubjectPublicKeyInfo structure
        -- SubjectPublicKeyInfo ::= SEQUENCE {
        --   algorithm         AlgorithmIdentifier,
        --   subjectPublicKey  BIT STRING
        -- }
        
        -- RSA algorithm identifier: 1.2.840.113549.1.1.1 (rsaEncryption)
        local rsaOID = "\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"  -- OID
        local nullParam = "\x05\x00"  -- NULL
        local algorithmSeq = ber.encode({ type = ber.Types.SEQUENCE, data = rsaOID .. nullParam })
        
        -- BIT STRING with no unused bits (0x00 prefix)
        local bitString = "\x00" .. publicKeyBer
        local bitStringBer = ber.encode({ type = ber.Types.BIT_STRING, data = bitString })
        
        local spkiSequence = algorithmSeq .. bitStringBer
        local spkiBer = ber.encode({ type = ber.Types.SEQUENCE, data = spkiSequence })
        
        -- Base64 encode and format as PEM
        local publicKeyB64 = CryptoLite.base64Encode(spkiBer)
        local pem = "-----BEGIN PUBLIC KEY-----\n"
        
        -- Split into 64-character lines
        for i = 1, #publicKeyB64, 64 do
            pem = pem .. publicKeyB64:sub(i, i + 63) .. "\n"
        end
        
        pem = pem .. "-----END PUBLIC KEY-----"
        return pem
    end
end

--[[
    Convert EC JWK to PEM format
    @param jwk: EC JWK object
    @return PEM: EC key in PEM format, or nil and error message
--]]
local function jwkECToPEM(jwk)
    -- Check for required parameters
    if not jwk.crv or not jwk.x or not jwk.y then
        error("CryptoLite.jwkECToPEM: EC JWK requires 'crv', 'x', and 'y' parameters")
    end
    
    -- Map JWK curve names to OIDs
    local curveOIDs = {
        ["P-256"] = "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07",  -- prime256v1 / secp256r1
        ["P-384"] = "\x06\x05\x2b\x81\x04\x00\x22",              -- secp384r1
        ["P-521"] = "\x06\x05\x2b\x81\x04\x00\x23",              -- secp521r1
        ["secp256k1"] = "\x06\x05\x2b\x81\x04\x00\x0a"           -- secp256k1
    }
    
    local curveOID = curveOIDs[jwk.crv]
    if not curveOID then
        error("CryptoLite.jwkECToPEM: unsupported EC curve: " .. jwk.crv)
    end
    
    -- Decode coordinates
    local x = CryptoLite.base64URLDecode(jwk.x)
    local y = CryptoLite.base64URLDecode(jwk.y)
    
    -- Check if this is a private key
    local isPrivate = jwk.d ~= nil
    
    if isPrivate then
        -- Private key
        local d = CryptoLite.base64URLDecode(jwk.d)
        
        -- ECPrivateKey ::= SEQUENCE {
        --   version        INTEGER { ecPrivkeyVer1(1) },
        --   privateKey     OCTET STRING,
        --   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        --   publicKey  [1] BIT STRING OPTIONAL
        -- }
        
        local version = "\x01"  -- Version 1
        local versionBer = ber.encode({ type = ber.Types.INTEGER, data = version })
        
        -- Private key as OCTET STRING
        local privateKeyBer = ber.encode({ type = ber.Types.OCTET_STRING, data = d })
        
        -- Parameters (curve OID) with explicit tag [0]
        local paramsBer = "\xa0" .. string.char(#curveOID) .. curveOID
        
        -- Public key (uncompressed point format: 0x04 || x || y) with explicit tag [1]
        local publicKeyPoint = "\x04" .. x .. y
        local publicKeyBitString = "\x00" .. publicKeyPoint  -- No unused bits
        local publicKeyBitStringBer = ber.encode({ type = ber.Types.BIT_STRING, data = publicKeyBitString })
        local publicKeyBer = "\xa1" .. string.char(#publicKeyBitStringBer) .. publicKeyBitStringBer
        
        -- Combine into SEQUENCE
        local sequence = versionBer .. privateKeyBer .. paramsBer .. publicKeyBer
        local privateKeySeqBer = ber.encode({ type = ber.Types.SEQUENCE, data = sequence })
        
        -- Base64 encode and format as PEM
        local privateKeyB64 = CryptoLite.base64Encode(privateKeySeqBer)
        local pem = "-----BEGIN EC PRIVATE KEY-----\n"
        
        -- Split into 64-character lines
        for i = 1, #privateKeyB64, 64 do
            pem = pem .. privateKeyB64:sub(i, i + 63) .. "\n"
        end
        
        pem = pem .. "-----END EC PRIVATE KEY-----"
        return pem
        
    else
        -- Public key
        -- Uncompressed point format: 0x04 || x || y
        local publicKeyPoint = "\x04" .. x .. y
        
        -- Wrap in SubjectPublicKeyInfo structure
        -- SubjectPublicKeyInfo ::= SEQUENCE {
        --   algorithm         AlgorithmIdentifier,
        --   subjectPublicKey  BIT STRING
        -- }
        
        -- EC algorithm identifier: 1.2.840.10045.2.1 (ecPublicKey)
        local ecOID = "\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
        local algorithmSeq = ber.encode({ type = ber.Types.SEQUENCE, data = ecOID .. curveOID })
        
        -- BIT STRING with no unused bits (0x00 prefix)
        local bitString = "\x00" .. publicKeyPoint
        local bitStringBer = ber.encode({ type = ber.Types.BIT_STRING, data = bitString })
        
        local spkiSequence = algorithmSeq .. bitStringBer
        local spkiBer = ber.encode({ type = ber.Types.SEQUENCE, data = spkiSequence })
        
        -- Base64 encode and format as PEM
        local publicKeyB64 = CryptoLite.base64Encode(spkiBer)
        local pem = "-----BEGIN PUBLIC KEY-----\n"
        
        -- Split into 64-character lines
        for i = 1, #publicKeyB64, 64 do
            pem = pem .. publicKeyB64:sub(i, i + 63) .. "\n"
        end
        
        pem = pem .. "-----END PUBLIC KEY-----"
        return pem
    end
end

--[[
    Convert EC public key data to JWK
    @param publicKeyData: EC public key point data
    @param curveOID: Curve OID
    @return jwk: JWK object or nil and error message
--]]
local function pemECPublicToJWK(publicKeyData, curveOID)
    --logger.debugLog("pemECPublicToJWK called with publicKeyData: " .. logger.dumpAsString(publicKeyData) .. " curveOID: " .. logger.dumpAsString(curveOID))
    if not curveOID then
        error("CryptoListe.pemECPublicToJWK: curve OID is required for EC public key")
    end
    
    -- Map OID to JWK curve name
    local oidToCurve = {
        ["\x2a\x86\x48\xce\x3d\x03\x01\x07"] = "P-256",  -- prime256v1 / secp256r1
        ["\x2b\x81\x04\x00\x22"] = "P-384",              -- secp384r1
        ["\x2b\x81\x04\x00\x23"] = "P-521",              -- secp521r1
        ["\x2b\x81\x04\x00\x0a"] = "secp256k1"           -- secp256k1
    }
    
    local crv = oidToCurve[curveOID]
    if not crv then
        error("CryptoLite.pemECPublicToJWK: unsupported EC curve OID")
    end
    
    -- Parse uncompressed point format: 0x04 || x || y
    if #publicKeyData < 3 or publicKeyData:byte(1) ~= 0x04 then
        error("CryptoLite.pemECPublicToJWK: unsupported EC point format (expected uncompressed)")
    end
    
    local coordLen = (#publicKeyData - 1) / 2
    local x = publicKeyData:sub(2, 1 + coordLen)
    local y = publicKeyData:sub(2 + coordLen)
    
    -- Build JWK
    local jwk = {
        kty = "EC",
        crv = crv,
        x = CryptoLite.base64URLEncode(x),
        y = CryptoLite.base64URLEncode(y)
    }
    
    return jwk
end

--[[
    Convert RSA public key data to JWK
    @param publicKeyData: RSA public key data from SubjectPublicKeyInfo
    @return jwk: JWK object or nil and error message
--]]
local function pemRSAPublicToJWK(publicKeyData)
    --logger.debugLog("pemRSAPublicToJWK called with publicKeyData: " .. logger.dumpAsString(publicKeyData))

    -- Parse RSAPublicKey structure
    -- RSAPublicKey ::= SEQUENCE {
    --   modulus           INTEGER,  -- n
    --   publicExponent    INTEGER   -- e
    -- }
    
    local decoded = ber.decode(publicKeyData)
    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemRSAPublicToJWK: invalid RSA public key structure")
    end
    
    if not decoded.children or #decoded.children < 2 then
        error("CryptoLite.pemRSAPublicToJWK: incomplete RSA public key structure")
    end
    
    -- Extract n and e
    local n = decoded.children[1].data
    local e = decoded.children[2].data
    
    -- Build JWK
    local jwk = {
        kty = "RSA",
        n = CryptoLite.base64URLEncode(n),
        e = CryptoLite.base64URLEncode(e)
    }
    
    return jwk
end

--[[
    Convert public key PEM to JWK (handles both RSA and EC)
    @param pem: Public key in PEM format
    @return jwk: JWK object or nil and error message
--]]
local function pemPublicToJWK(pem)
    -- Extract base64 content between headers
    local b64 = pem:match("%-%-%-%-%-BEGIN PUBLIC KEY%-%-%-%-%-\n(.-)%-%-%-%-%-END PUBLIC KEY%-%-%-%-%-")
    if not b64 then
        error("CryptoLite.pemPublicToJWK: invalid public key PEM format")
    end
    
    -- Remove whitespace and decode
    b64 = b64:gsub("%s+", "")
    local der = CryptoLite.base64Decode(b64)
    
    -- Parse SubjectPublicKeyInfo structure
    -- SubjectPublicKeyInfo ::= SEQUENCE {
    --   algorithm         AlgorithmIdentifier,
    --   subjectPublicKey  BIT STRING
    -- }
    
    local decoded = ber.decode(der)
    --logger.debugLog("CryptoLite.pemPublicToJWK decoded: " .. logger.dumpAsString(decoded))
    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemPublicToJWK: invalid public key structure")
    end
    
    if not decoded.children or #decoded.children < 2 then
        error("CryptoLite.pemPublicToJWK: incomplete public key structure")
    end
    
    -- Extract algorithm identifier
    local algorithm = decoded.children[1]
    if not algorithm or algorithm.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemPublicToJWK: invalid algorithm identifier")
    end
    --logger.debugLog("CryptoLite.pemPublicToJWK algorithm: " .. logger.dumpAsString(algorithm))
    
    -- Extract algorithm OID
    local algorithmOID = nil
    local curveOID = nil
    if algorithm.children and #algorithm.children > 0 then
        algorithmOID = algorithm.children[1].data
        
        -- For EC keys, the curve OID is the second element
        if #algorithm.children > 1 then
            curveOID = algorithm.children[2].data
        end
    end
    --logger.debugLog("CryptoLite.pemPublicToJWK algorithmOID: " .. logger.dumpAsString(algorithmOID) .. " curveOID: " .. logger.dumpAsString(curveOID))
    if not algorithmOID then
        error("CryptoLite.pemPublicToJWK: unable to determine algorithm OID")
    end
    
    -- Extract public key BIT STRING
    local publicKeyBitString = decoded.children[2]
    if not publicKeyBitString or publicKeyBitString.type ~= ber.Types.BIT_STRING then
        error("CryptoLite.pemPublicToJWK: invalid public key bit string")
    end
    --logger.debugLog("CryptoLite.pemPublicToJWK publicKeyBitString: " .. logger.dumpAsString(publicKeyBitString))

    
    -- Skip the first byte (unused bits indicator)
    local publicKeyData = publicKeyBitString.data:sub(2)
    --logger.debugLog("CryptoLite.pemPublicToJWK publicKeyData: " .. logger.dumpAsString(publicKeyData))
    
    -- Determine key type from algorithm OID
    -- RSA: 1.2.840.113549.1.1.1 = 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x01
    -- EC:  1.2.840.10045.2.1 = 0x2a 0x86 0x48 0xce 0x3d 0x02 0x01
    
    if algorithmOID == "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" then
        -- RSA public key
        return pemRSAPublicToJWK(publicKeyData)
    elseif algorithmOID == "\x2a\x86\x48\xce\x3d\x02\x01" then
        -- EC public key
        return pemECPublicToJWK(publicKeyData, curveOID)
    else
        error("CryptoLite.pemPublicToJWK: unsupported algorithm OID")
    end
end

--[[
    Convert JWK to PEM format
    @param jwk: The JSON web key. Can be an ECDSA public or private key, or an RSA public or private key
    @return PEM: The public or private key in PEM format, or nil and error message
    
    Supports:
    - RSA public keys (kty="RSA", n, e)
    - RSA private keys (kty="RSA", n, e, d, p, q, dp, dq, qi)
    - EC public keys (kty="EC", crv, x, y)
    - EC private keys (kty="EC", crv, x, y, d)
    - X.509 certificates (x5c array)
--]]
function CryptoLite.jwkToPEM(jwk)
    if not jwk then
        error("CryptoLite.jwkToPEM: jwk is required")
    end
    
    -- Handle x5c (X.509 certificate chain) - use the first certificate
    if jwk.x5c and type(jwk.x5c) == "table" and #jwk.x5c > 0 then
        local cert = jwk.x5c[1]
        -- Remove any whitespace and ensure proper formatting
        cert = cert:gsub("%s+", "")
        return "-----BEGIN CERTIFICATE-----\n" .. cert .. "\n-----END CERTIFICATE-----"
    end
    
    -- Determine key type
    local kty = jwk.kty
    if not kty then
        error("CryptoLite.jwkToPEM: jwk.kty (key type) is required")
    end
    
    if kty == "RSA" then
        return jwkRSAToPEM(jwk)
    elseif kty == "EC" then
        return jwkECToPEM(jwk)
    else
        error("CryptoLite.jwkToPEM: unsupported key type: " .. kty)
    end
end

--[[
    Convert RSA private key PEM to JWK
    @param pem: RSA private key in PEM format
    @return jwk: JWK object or nil and error message
--]]
local function pemRSAPrivateToJWK(pem)
    -- Extract base64 content between headers
    local b64 = pem:match("%-%-%-%-%-BEGIN RSA PRIVATE KEY%-%-%-%-%-\n(.-)%-%-%-%-%-END RSA PRIVATE KEY%-%-%-%-%-")
    if not b64 then
        error("CryptoLite.pemRSAPrivateToJWK: invalid RSA private key PEM format")
    end
    
    -- Remove whitespace and decode
    b64 = b64:gsub("%s+", "")
    local der = CryptoLite.base64Decode(b64)
    
    -- Parse ASN.1 structure
    -- RSAPrivateKey ::= SEQUENCE {
    --   version           Version (0),
    --   modulus           INTEGER,  -- n
    --   publicExponent    INTEGER,  -- e
    --   privateExponent   INTEGER,  -- d
    --   prime1            INTEGER,  -- p
    --   prime2            INTEGER,  -- q
    --   exponent1         INTEGER,  -- dp
    --   exponent2         INTEGER,  -- dq
    --   coefficient       INTEGER   -- qi
    -- }
    
    local decoded = ber.decode(der)
    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemRSAPrivateToJWK: invalid RSA private key structure")
    end
    
    if not decoded.children or #decoded.children < 9 then
        error("CryptoLite.pemRSAPrivateToJWK: incomplete RSA private key structure")
    end
    
    -- Extract components (skip version at index 1)
    local n = decoded.children[2].data
    local e = decoded.children[3].data
    local d = decoded.children[4].data
    local p = decoded.children[5].data
    local q = decoded.children[6].data
    local dp = decoded.children[7].data
    local dq = decoded.children[8].data
    local qi = decoded.children[9].data
    
    -- Build JWK
    local jwk = {
        kty = "RSA",
        n = CryptoLite.base64URLEncode(n),
        e = CryptoLite.base64URLEncode(e),
        d = CryptoLite.base64URLEncode(d),
        p = CryptoLite.base64URLEncode(p),
        q = CryptoLite.base64URLEncode(q),
        dp = CryptoLite.base64URLEncode(dp),
        dq = CryptoLite.base64URLEncode(dq),
        qi = CryptoLite.base64URLEncode(qi)
    }
    
    return jwk
end


--[[
    Convert EC private key PEM to JWK
    @param pem: EC private key in PEM format
    @return jwk: JWK object or nil and error message
--]]
local function pemECPrivateToJWK(pem)
    -- Extract base64 content between headers
    local b64 = pem:match("%-%-%-%-%-BEGIN EC PRIVATE KEY%-%-%-%-%-\n(.-)%-%-%-%-%-END EC PRIVATE KEY%-%-%-%-%-")
    if not b64 then
        error("CryptoLite.pemECPrivateToJWK: invalid EC private key PEM format")
    end
    
    -- Remove whitespace and decode
    b64 = b64:gsub("%s+", "")
    local der = CryptoLite.base64Decode(b64)
    
    -- Parse ASN.1 structure
    -- ECPrivateKey ::= SEQUENCE {
    --   version        INTEGER { ecPrivkeyVer1(1) },
    --   privateKey     OCTET STRING,
    --   parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
    --   publicKey  [1] BIT STRING OPTIONAL
    -- }
    
    local decoded = ber.decode(der)
    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemECPrivateToJWK: invalid EC private key structure")
    end
    
    if not decoded.children or #decoded.children < 2 then
        error("CryptoLite.pemECPrivateToJWK: incomplete EC private key structure")
    end
    
    -- Extract private key (d)
    local d = decoded.children[2].data
    
    -- Extract curve OID from parameters [0]
    local curveOID = nil
    local publicKeyPoint = nil
    
    for i = 3, #decoded.children do
        local child = decoded.children[i]
        -- Parameters with tag [0] (0xa0)
        if child.class == 2 and child.type == 0 then
            -- Extract OID from the parameters
            local paramData = child.data
            if paramData and #paramData > 2 and paramData:byte(1) == 0x06 then
                local oidLen = paramData:byte(2)
                curveOID = paramData:sub(3, 2 + oidLen)
            end
        end
        -- Public key with tag [1] (0xa1)
        if child.class == 2 and child.type == 1 then
            -- Extract public key point from BIT STRING
            local pubKeyData = child.data
            if pubKeyData then
                local bitStringDecoded = ber.decode(pubKeyData)
                if bitStringDecoded and bitStringDecoded.type == ber.Types.BIT_STRING then
                    -- Skip the first byte (unused bits indicator) and the 0x04 prefix
                    publicKeyPoint = bitStringDecoded.data:sub(2)
                end
            end
        end
    end
    
    if not curveOID then
        error("CryptoLite.pemECPrivateToJWK: curve OID not found in EC private key")
    end
    
    -- Map OID to JWK curve name
    local oidToCurve = {
        ["\x2a\x86\x48\xce\x3d\x03\x01\x07"] = "P-256",  -- prime256v1 / secp256r1
        ["\x2b\x81\x04\x00\x22"] = "P-384",              -- secp384r1
        ["\x2b\x81\x04\x00\x23"] = "P-521",              -- secp521r1
        ["\x2b\x81\x04\x00\x0a"] = "secp256k1"           -- secp256k1
    }
    
    local crv = oidToCurve[curveOID]
    if not crv then
        error("CryptoLite.pemECPrivateToJWK: unsupported EC curve OID")
    end
    
    -- If public key point is available, extract x and y
    local x, y
    if publicKeyPoint and #publicKeyPoint > 0 then
        -- Uncompressed point format: 0x04 || x || y
        if publicKeyPoint:byte(1) == 0x04 then
            local coordLen = (#publicKeyPoint - 1) / 2
            x = publicKeyPoint:sub(2, 1 + coordLen)
            y = publicKeyPoint:sub(2 + coordLen)
        end
    end
    
    -- If we don't have x and y, we need to derive them from the private key
    -- For now, we'll require them to be present in the PEM
    if not x or not y then
        -- Try to derive public key from private key using openssl
        local privKey = pkey.new(pem)
        if privKey then
            local pubPem = privKey:toPEM("public")
            local pubJwk = pemPublicToJWK(pubPem)
            if pubJwk then
                x = CryptoLite.base64URLDecode(pubJwk.x)
                y = CryptoLite.base64URLDecode(pubJwk.y)
            end
        end
    end
    
    if not x or not y then
        error("CryptoLite.pemECPrivateToJWK: could not extract or derive public key coordinates")
    end
    
    -- Build JWK
    local jwk = {
        kty = "EC",
        crv = crv,
        x = CryptoLite.base64URLEncode(x),
        y = CryptoLite.base64URLEncode(y),
        d = CryptoLite.base64URLEncode(d)
    }
    
    return jwk
end

--[[
    Convert EC private key data to JWK (from PKCS#8 inner structure)
    @param privateKeyData: EC private key data
    @param curveOID: Curve OID from PKCS#8 algorithm identifier
    @param fullPem: Full PEM string for fallback public key derivation
    @return jwk: JWK object or nil and error message
--]]
local function pemECPrivateDataToJWK(privateKeyData, curveOID, fullPem)
    if not curveOID then
        error("CryptoLite.pemECPrivateDataToJWK: curve OID is required for EC private key in PKCS#8")
    end
    
    -- Parse ECPrivateKey structure
    local decoded = ber.decode(privateKeyData)
    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemECPrivateDataToJWK: invalid EC private key structure in PKCS#8")
    end
    
    if not decoded.children or #decoded.children < 2 then
        error("CryptoLite.pemECPrivateDataToJWK: incomplete EC private key structure in PKCS#8")
    end
    
    -- Extract private key (d) - second element is OCTET STRING
    local d = decoded.children[2].data
    
    -- Extract public key point if present (optional [1] tagged element)
    local publicKeyPoint = nil
    for i = 3, #decoded.children do
        local child = decoded.children[i]
        -- Public key with tag [1] (0xa1)
        if child.class == 2 and child.type == 1 then
            -- Extract public key point from BIT STRING
            local pubKeyData = child.data
            if pubKeyData then
                local bitStringDecoded = ber.decode(pubKeyData)
                if bitStringDecoded and bitStringDecoded.type == ber.Types.BIT_STRING then
                    -- Skip the first byte (unused bits indicator)
                    publicKeyPoint = bitStringDecoded.data:sub(2)
                end
            end
        end
    end
    
    -- Map OID to JWK curve name
    local oidToCurve = {
        ["\x2a\x86\x48\xce\x3d\x03\x01\x07"] = "P-256",  -- prime256v1 / secp256r1
        ["\x2b\x81\x04\x00\x22"] = "P-384",              -- secp384r1
        ["\x2b\x81\x04\x00\x23"] = "P-521",              -- secp521r1
        ["\x2b\x81\x04\x00\x0a"] = "secp256k1"           -- secp256k1
    }
    
    local crv = oidToCurve[curveOID]
    if not crv then
        error("CryptoLite.pemECPrivateDataToJWK: unsupported EC curve OID in PKCS#8")
    end
    
    -- If public key point is available, extract x and y
    local x, y
    if publicKeyPoint and #publicKeyPoint > 0 then
        -- Uncompressed point format: 0x04 || x || y
        if publicKeyPoint:byte(1) == 0x04 then
            local coordLen = (#publicKeyPoint - 1) / 2
            x = publicKeyPoint:sub(2, 1 + coordLen)
            y = publicKeyPoint:sub(2 + coordLen)
        end
    end
    
    -- If we don't have x and y, derive them from the private key using openssl
    if not x or not y then
        local success, privKey = pcall(pkey.new, fullPem)
        if success and privKey then
            local pubPem = privKey:toPEM("public")
            local pubJwk = pemPublicToJWK(pubPem)
            if pubJwk then
                x = CryptoLite.base64URLDecode(pubJwk.x)
                y = CryptoLite.base64URLDecode(pubJwk.y)
            end
        end
    end
    
    if not x or not y then
        error("CryptoLite.pemECPrivateDataToJWK: could not extract or derive public key coordinates from PKCS#8")
    end
    
    -- Build JWK
    local jwk = {
        kty = "EC",
        crv = crv,
        x = CryptoLite.base64URLEncode(x),
        y = CryptoLite.base64URLEncode(y),
        d = CryptoLite.base64URLEncode(d)
    }
    
    return jwk
end

--[[
    Convert RSA private key data to JWK (from PKCS#8 inner structure)
    @param privateKeyData: RSA private key data
    @return jwk: JWK object or nil and error message
--]]
local function pemRSAPrivateDataToJWK(privateKeyData)
    -- Parse RSAPrivateKey structure
    local decoded = ber.decode(privateKeyData)
    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemRSAPrivateDataToJWK: invalid RSA private key structure in PKCS#8")
    end
    
    if not decoded.children or #decoded.children < 9 then
        error("CryptoLite.pemRSAPrivateDataToJWK: incomplete RSA private key structure in PKCS#8")
    end
    
    -- Extract components (skip version at index 1)
    local n = decoded.children[2].data
    local e = decoded.children[3].data
    local d = decoded.children[4].data
    local p = decoded.children[5].data
    local q = decoded.children[6].data
    local dp = decoded.children[7].data
    local dq = decoded.children[8].data
    local qi = decoded.children[9].data
    
    -- Build JWK
    local jwk = {
        kty = "RSA",
        n = CryptoLite.base64URLEncode(n),
        e = CryptoLite.base64URLEncode(e),
        d = CryptoLite.base64URLEncode(d),
        p = CryptoLite.base64URLEncode(p),
        q = CryptoLite.base64URLEncode(q),
        dp = CryptoLite.base64URLEncode(dp),
        dq = CryptoLite.base64URLEncode(dq),
        qi = CryptoLite.base64URLEncode(qi)
    }
    
    return jwk
end

--[[
    Convert PKCS#8 private key PEM to JWK (handles both RSA and EC)
    @param pem: PKCS#8 private key in PEM format
    @return jwk: JWK object or nil and error message
--]]
local function pemPKCS8PrivateToJWK(pem)
    -- Extract base64 content between headers
    local b64 = pem:match("%-%-%-%-%-BEGIN PRIVATE KEY%-%-%-%-%-\n(.-)%-%-%-%-%-END PRIVATE KEY%-%-%-%-%-")
    if not b64 then
        error("CryptoLite.pemPKCS8PrivateToJWK: CryptoLite.pemPKCS8PrivateToJWK invalid PKCS#8 private key PEM format")
    end
    
    -- Remove whitespace and decode
    b64 = b64:gsub("%s+", "")
    local der = CryptoLite.base64Decode(b64)
    
    -- Parse PKCS#8 PrivateKeyInfo structure
    -- PrivateKeyInfo ::= SEQUENCE {
    --   version         Version,
    --   algorithm       AlgorithmIdentifier,
    --   privateKey      OCTET STRING
    -- }
    
    local decoded = ber.decode(der)

    if not decoded or decoded.type ~= ber.Types.SEQUENCE then
        return nil, "CryptoLite.pemPKCS8PrivateToJWK invalid PKCS#8 private key structure"
    end
    
    if not decoded.children or #decoded.children < 3 then
        return nil, "CryptoLite.pemPKCS8PrivateToJWK incomplete PKCS#8 private key structure"
    end
    
    -- Extract algorithm identifier (first or second element depending on version)
    local algorithm = decoded.children[1]
    local privateKeyOctetString = decoded.children[2]
    
    -- Check if first element is version (INTEGER)
    if algorithm.type == ber.Types.INTEGER then
        -- Version is present, algorithm is second element
        algorithm = decoded.children[2]
        privateKeyOctetString = decoded.children[3]
    end
    
    if not algorithm or algorithm.type ~= ber.Types.SEQUENCE then
        error("CryptoLite.pemPKCS8PrivateToJWK: invalid algorithm identifier in PKCS#8")
    end
    
    -- Extract algorithm OID
    local algorithmOID = nil
    local curveOID = nil
    if algorithm.children and #algorithm.children > 0 then
        algorithmOID = algorithm.children[1].data
        
        -- For EC keys, the curve OID is the second element
        if #algorithm.children > 1 then
            curveOID = algorithm.children[2].data
        end
    end

    -- Extract private key OCTET STRING
    if not privateKeyOctetString or privateKeyOctetString.type ~= ber.Types.OCTET_STRING then
        error("CryptoLite.pemPKCS8PrivateToJWK: invalid private key octet string in PKCS#8")
    end
    
    local privateKeyData = privateKeyOctetString.data
    
    -- Determine key type from algorithm OID
    -- RSA: 1.2.840.113549.1.1.1 = 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x01
    -- EC:  1.2.840.10045.2.1 = 0x2a 0x86 0x48 0xce 0x3d 0x02 0x01
    
    if algorithmOID == "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" then
        -- RSA private key - the privateKeyData contains the RSAPrivateKey structure
        return pemRSAPrivateDataToJWK(privateKeyData)
    elseif algorithmOID == "\x2a\x86\x48\xce\x3d\x02\x01" then
        -- EC private key - the privateKeyData contains the ECPrivateKey structure
        return pemECPrivateDataToJWK(privateKeyData, curveOID, pem)
    else
        error("CryptoLite.pemPKCS8PrivateToJWK: unsupported algorithm OID in PKCS#8")
    end
end

--[[
    Convert PEM to JWK format
    @param pem: The PEM-encoded key (public or private, RSA or EC)
    @return jwk: The JSON web key object, or nil and error message
    
    Supports:
    - RSA public keys (BEGIN PUBLIC KEY with RSA algorithm)
    - RSA private keys (BEGIN RSA PRIVATE KEY or BEGIN PRIVATE KEY)
    - EC public keys (BEGIN PUBLIC KEY with EC algorithm)
    - EC private keys (BEGIN EC PRIVATE KEY or BEGIN PRIVATE KEY)
--]]
function CryptoLite.PEMtoJWK(pem)

    if not pem then
        error("CryptoLite.PEMtoJWK: pem is required")
    end
    
    -- Remove whitespace and normalize line endings
    pem = pem:gsub("\r\n", "\n"):gsub("\r", "\n")
    
    -- Determine key type from PEM headers
    if pem:match("%-%-%-%-%-BEGIN RSA PRIVATE KEY%-%-%-%-%-") then
        return pemRSAPrivateToJWK(pem)
    elseif pem:match("%-%-%-%-%-BEGIN EC PRIVATE KEY%-%-%-%-%-") then
        return pemECPrivateToJWK(pem)
    elseif pem:match("%-%-%-%-%-BEGIN PRIVATE KEY%-%-%-%-%-") then
        -- PKCS#8 format - need to determine if RSA or EC
        return pemPKCS8PrivateToJWK(pem)
    elseif pem:match("%-%-%-%-%-BEGIN PUBLIC KEY%-%-%-%-%-") then
        return pemPublicToJWK(pem)
    else
        logger.debugLog("CryptoLite.PEMtoJWK failed: unsupported PEM format or unrecognized key type")
        error("CryptoLite.PEMtoJWK: unsupported PEM format or unrecognized key type")
    end
end


--[[
    ============================================================================
    JWE encryption and decryption utilities
    ============================================================================
--]]


--[[
    Generate an encrypted JWE string
    
    @param options: Table with the following fields:
        - plaintext (string, required): plaintext string to encrypt
        - encryptionAlgorithm (string, required): "RSA-OAEP", "ECDH-ES", or "dir"
        - encryptionKey (string, required): Public key PEM (RSA/EC) or shared secret (dir)
        - encryptionMethod (string, requried): e.g. "A256GCM" - must be a supported content encryption algorithm from CryptoLite
        - kid (string, optional): Key ID for JWE header
        - cty (string, options): cty to add to the JWE header if provided
        - apu (string, options): apu to add to the JWE header if provided
        - apv (string, options): apv to add to the JWE header if provided
        - zip (boolean, optional): whether or not to use zip default compression of the plaintext prior to encryption. Default: false
    
    @return jwe: Encrypted JWT string or throws error
    @return error: Error message if generation failed
    
    Example:
        local jwe, err = CryptoLite.generateJWE({
            plaintext = "Test string"
            encryptionAlgorithm = "RSA-OAEP",
            encryptionKey = recipientPublicKeyPEM,
            encryptionMethod = "A256GCM",
            zip = true
        })
--]]
function CryptoLite.generateJWE(options)
    if not options then
        error("CryptoLite.generateJWE: options are required")
    end

    if not options.plaintext then
        logger.debugLog("CryptoLite.generateJWE options: " .. logger.dumpAsString(options))
        error("CryptoLite.generateJWE: plaintext is required")
    end

    if not options.encryptionAlgorithm then
        error("CryptoLite.generateJWE: encryptionAlgorithm is required")
    end
    
    if not options.encryptionKey then
        error("CryptoLite.generateJWE: encryptionKey is required")
    end
    
    local encAlg = options.encryptionAlgorithm
    
    -- Validate encryption algorithm
    if not CryptoLite.isSupportedEncryptionKeyAgreementAlgorithm(encAlg) then
        error("CryptoLite.generateJWE: unsupported encryption algorithm: " .. logger.dumpAsString(encAlg))
    end

        -- Validate encryption method
    local encMethod = options.encryptionMethod
    if not CryptoLite.isSupportedContentEncryptionAlgorithm(encMethod) then
        error("CryptoLite.generateJWE: unsupported encryption method: " .. logger.dumpAsString(encMethod))
    end
    
    -- Step 1: Encrypt the plaintext
    local success, encrypted, textToEncrypt

    -- generate JWE header - required now to figure out additional authentication data
    -- note this does get updated to add the epk when using ECDH-ES as the encryption algorithm
    local jweHeader = {
        alg = encAlg,
        enc = encMethod,
        typ = "JWE"
    }
    if options.cty then
        jweHeader.cty = options.cty
    end
    if options.kid then
        jweHeader.kid = options.kid
    end
    if options.apu then
        jweHeader.apu = options.apu
    end
    if options.apv then
        jweHeader.apv = options.apv
    end
    if options.zip then
        jweHeader.zip = "DEF"
        textToEncrypt = libDeflate:CompressDeflate(jwt)
    else
        textToEncrypt = options.plaintext
    end
    
    local success, jweHeaderStr = pcall(cjson.encode, jweHeader)
    if not success then
        error("CryptoLite.generateJWE: failed to encode JWE header: " .. tostring(jweHeaderStr))
    end
    local jweHeaderB64U = CryptoLite.base64URLEncode(jweHeaderStr)

    if encAlg == "dir" then
        -- Direct encryption with shared secret - not yet supported
        error("CryptoLite.generateJWE: direct encryption not supported")
    else
        -- must be an RSA or EC based algorithm

        --
        -- If ECDH based algorithm, generate the ephemeral key first, since we need to create the JWE 
        -- header with the public key in it this should be on the same curve as recipientPublicKeyPEM
        --
        local ephemeralKey = nil
        if CryptoLite.isECDHEncryptionKeyAgreement(encAlg) then
            -- Get the curve name from the recipient's key
            local curveInfo = CryptoLite.determineECKeyProperties(options.encryptionKey)
        
            -- Generate ephemeral key pair on the same curve
            local genParams = {
                type = "EC",
                curve = curveInfo.curveName
            }

            ephemeralKey = pkey.new(genParams)

            -- get the JWK format of the public key of the ephemeralKey to form part of the JWE header
            local epk = CryptoLite.PEMtoJWK(ephemeralKey:toPEM("public"))
            --logger.debugLog("CryptoLite.generateJWE epk: " .. logger.dumpAsString(epk))

            -- update the JWE header and its base64-url encoded representation to include the epk
            jweHeader.epk = epk
            jweHeaderB64U = CryptoLite.base64URLEncode(cjson.encode(jweHeader))
        end

        -- Encrypt the textToEncrypt with requested encryption key agreement and content encryption algorithm
        --logger.debugLog("CryptoLite.generateJWE: About to call CryptoLite.encrypt: plaintext: " .. logger.dumpAsString(textToEncrypt) .. " key: " .. logger.dumpAsString(options.encryptionKey))

        local encryptResults = CryptoLite.encrypt({
            plaintext = textToEncrypt,
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
            encryptedKeyB64U = CryptoLite.base64URLEncode(encryptResults.encryptedKey)
        end

        -- put the bits together
        encrypted = encryptedKeyB64U .. "." .. CryptoLite.base64URLEncode(encryptResults.iv) .. "." .. CryptoLite.base64URLEncode(encryptResults.ciphertext) .. "." .. CryptoLite.base64URLEncode(encryptResults.tag)        
    end
    
    -- Step 2: Create JWE structure
    -- Format: {base64url(JWE_header)}.{encrypted_jwt}
    
    -- Return JWE format
    local result = jweHeaderB64U .. "." .. encrypted
    --logger.debugLog("CryptoLite.generateJWE returning: " .. result)
    return result
end

--[[
    Decrypt an encrypted JWE string
    
    @param options: Table with the following fields:
        - jwe (string, required): The JWE string to decrypt
        - encryptionAlgorithm (string, required): Expected encryption algorithm
        - decryptionKey (string, required): Private key PEM (RSA/EC) or shared secret (dir)
        - encryptionMethod (string, required): Expected encryption method - "A256GCM"
    
    @return result: Table with jweHeader, plaintext or throws an error on failure with an error message
    
    Example:
        local result = CryptoLite.decryptJWE({
            jwe = jweString,
            encryptionAlgorithm = "RSA-OAEP",
            decryptionKey = privateKeyPEM,
            encryptionMethod = "A256GCM"
        })
--]]
function CryptoLite.decryptJWE(options)

    if not options or not options.jwe then
        error("CryptoLite.decryptJWE: jwe is required")
    end
    
    -- Validate encryption algorithm
    local encAlg = options.encryptionAlgorithm
    if not CryptoLite.isSupportedEncryptionKeyAgreementAlgorithm(encAlg) then
        error("CryptoLite.decryptJWE: unsupported encryption algorithm: " .. logger.dumpAsString(encAlg))
    end

        -- Validate encryption method
    local encMethod = options.encryptionMethod
    if not CryptoLite.isSupportedContentEncryptionAlgorithm(encMethod) then
        error("CryptoLite.decryptJWE: unsupported encryption method: " .. logger.dumpAsString(encMethod))
    end
    
    if not options.decryptionKey then
        error("CryptoLite.decryptJWE: decryptionKey is required")
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
        error("CryptoLite.decryptJWE: invalid JWE format: expected 4 dots, got " .. dotCount)
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
    local success, jweHeaderJSON = pcall(CryptoLite.base64URLDecode, jweHeaderEncoded)
    if not success then
        error("CryptoLite.decryptJWE: failed to decode JWE header: " .. tostring(jweHeaderJSON))
    end
    local success, encryptedKey = pcall(CryptoLite.base64URLDecode, encryptedKeyEncoded)
    if not success then
        error("CryptoLite.decryptJWE: failed to decode encryptedKey: " .. tostring(encryptedKey))
    end
    local success, iv = pcall(CryptoLite.base64URLDecode, ivEncoded)
    if not success then
        error("CryptoLite.decryptJWE: failed to decode iv: " .. tostring(iv))
    end
    local success, encryptedJWS = pcall(CryptoLite.base64URLDecode, encryptedJWSEncoded)
    if not success then
        error("CryptoLite.decryptJWE: failed to decode encryptedJWS: " .. tostring(encryptedJWS))
    end
    local success, tag = pcall(CryptoLite.base64URLDecode, tagEncoded)
    if not success then
        error("CryptoLite.decryptJWE: failed to decode tag: " .. tostring(tag))
    end

    -- process JWE header
    local success, jweHeader = pcall(cjson.decode, jweHeaderJSON)
    if not success then
        error("CryptoLite.decryptJWE: failed to parse JWE header JSON: " .. tostring(jweHeader))
    end
    
    -- Verify encryption algorithm matches
    if jweHeader.alg ~= encAlg then
        error("CryptoLite.decryptJWE: encryption algorithm mismatch: expected " .. encAlg .. ", got " .. jweHeader.alg)
    end

    -- Verify encryption method matches
    if jweHeader.enc ~= encMethod then
        error("CryptoLite.decryptJWE: encryption method mismatch: expected " .. encMethod .. ", got " .. jweHeader.enc)
    end
    
    -- Step 2: Decrypt the JWE
    local plaintext
    if encAlg == "dir" then
        error("CryptoLite.decryptJWE: Direct decryption not supported")
    else
        -- must be an RS or EC algorithm - decrypt the JWE

        -- if this is an ECDH algorithm, then we need the ephemeralPublicKey information to decrypt
        local ephemeralKeyPublicPEM = nil
        if CryptoLite.isECDHEncryptionKeyAgreement(encAlg) then
            -- extract the epk from the JWE header
            if not jweHeader.epk then
                return false, nil, nil, "CryptoLite.decryptJWE: JWE header missing epk"
            end
            -- and convert PEM
            local success, epkPEM = pcall(CryptoLite.jwkToPEM, jweHeader.epk)
            if not success then
                return false, nil, nil, "CryptoLite.decryptJWE: Invalid epk: " .. tostring(epkPEM)
            end
            ephemeralKeyPublicPEM = epkPEM
        end

        -- perform decryption of encryptedJWS to plaintext
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
        local success, decryptedJWS = pcall(CryptoLite.decrypt, decryptOptions)
        if not success then
            error("CryptoLite.decryptJWE: Decryption of JWS to plaintext failed: " .. tostring(decryptedJWS))
        end
        plaintext = decryptedJWS
    end

    -- Step 3: If the plaintext is zip'd, deflate it
    if jweHeader.zip == "DEF" then
        --logger.debugLog("CryptoLite.decryptJWE: Deflating plaintext")
        plaintext = libDeflate:DecompressDeflate(plaintext)
    end
    
    -- Step 4: Compose the results
    local decryptResults = {
        jweHeader = jweHeader,
        plaintext = plaintext
    }
    return decryptResults
end

return CryptoLite
