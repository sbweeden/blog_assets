--[[
        A HTTP transformation that is used to exercise the CryptoLite functions

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        testcryptolite = testcryptolite.lua

        [http-transformations:testcryptolite]
        request-match = request:GET /testcryptolite *
        =============

        Then in a browser just https://yourwebseal.com/testcryptolite
--]]
local logger = require 'LoggingUtils'
local cryptoLite = require 'CryptoLite'
local cjson = require "cjson"
local baseutils = require "basexx"

function preBlockWithTitle(title, text)
    return "<div style='border: 1px solid black; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end

function errorBlockWithTitle(title, text)
    return "<div style='border: 1px solid red; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end

function createResultBlock(title, text, success)
    if (success) then
        return preBlockWithTitle(title, text)
    else
        return errorBlockWithTitle(title .. " FAILED", text)
    end
end

function testJWTSignature(alg, signatureKey, verifyKey)
    local jwtHeader = {
            alg = alg,
            typ = "JWT"
    }
    local jwtClaims = {
            sub = "testuser"
    }
    local signatureBaseString = cryptoLite.base64URLEncode(cjson.encode(jwtHeader)).."."..cryptoLite.base64URLEncode(cjson.encode(jwtClaims))
    local success, signatureB64U = pcall(cryptoLite.sign, signatureBaseString, signatureKey, alg)
    if (success) then
        local jwtStr = signatureBaseString.."."..signatureB64U
        local success, verifyResult = pcall(cryptoLite.verify, signatureBaseString, signatureB64U, verifyKey, alg)
        if (success) then
            local jwtSignatureText = jwtStr .. "\nsignature verification result: " .. logger.dumpAsString(verifyResult)

            if (verifyResult) then
                return preBlockWithTitle("JWT signature test with algorithm: " .. jwtHeader["alg"], jwtSignatureText)
            else
                return errorBlockWithTitle("JWT signature test with algorithm: " .. jwtHeader["alg"] .. " FAILED", jwtSignatureText)
            end
        else
            return errorBlockWithTitle("JWT signature test with algorithm: " .. jwtHeader["alg"] .. " FAILED", "Failed during verify operation: " .. logger.dumpAsString(verifyResult))
        end
    else
        return errorBlockWithTitle("JWT signature test with algorithm: " .. jwtHeader["alg"] .. " FAILED", "Failed during sign operation: " .. logger.dumpAsString(signatureB64U))
    end
end


logger.debugLog("testcryptolite")

local rspBody = '<html><head><meta charset="utf-8"></head><body>'

-- test whether the new features are in place
local featureSupport = cryptoLite.checkFeatures()
local aadSupport = featureSupport.hasAADSupport
local ecDeriveSupport = featureSupport.hasECDeriveSupport
local supportText = "hasAADSupport(): " .. tostring(aadSupport) .. "\nhasECDervie(): " .. tostring(ecDeriveSupport)
rspBody = rspBody .. createResultBlock("Feature support", supportText, aadSupport and ecDeriveSupport)

-- hash of some random bytes
local randBytes = cryptoLite.randomBytes(10)
local hrb = cryptoLite.sha256(randBytes)
local hashText = "random bytes: " .. logger.dumpAsString(randBytes) .. "\n" .. "hash: " .. logger.dumpAsString(hrb)

rspBody = rspBody .. createResultBlock("SHA256 hash of random bytes", hashText, true)

-- string to byte array and back
local testString = "Héllö €—"
local expectedBytes = cjson.decode('[72, 195, 169, 108, 108, 195, 182, 32, 226, 130, 172, 226, 128, 148]')
local expectedBytesHex = cryptoLite.BAtohex(expectedBytes)
local calculatedBytesHex = cryptoLite.BAtohex(cryptoLite.utf8toBA(testString))
local testString2 = cryptoLite.BAtoutf8(expectedBytes)
local utf8Text = "testString: " .. testString .. "\nexpectedBytesHex: " .. expectedBytesHex .. "\ncalculatedBytesHex: " .. calculatedBytesHex .. "\nhex bytes equal: " .. tostring(expectedBytesHex == calculatedBytesHex) .. "\ntestString2: " .. testString2 .. "\nstringsEqual: " .. tostring(testString == testString2)
local valid = testString == testString2
rspBody = rspBody .. createResultBlock("UTF8 string to bytes and back", utf8Text, valid)

-- test of concatKDF
-- http://tools.ietf.org/html/rfc7518#appendix-C
local Z = cjson.decode("[158, 86, 217, 29, 129, 113, 53, 211, 114, 131, 66, 131, 191, 132, 38, 156, 251, 49, 110, 163, 218, 128, 106, 72, 246, 218, 167, 121, 140, 254, 144, 196]")
local ZByteString = cryptoLite.BAtoByteString(Z)

local keyLength = 128
local algId = "A128GCM"
local producer = "Alice"
local consumer = "Bob"
local pubInfo = 128

local derivedKey = cryptoLite.concatKDF({
    sharedSecret = ZByteString,
    keyDataLen = keyLength,
    algorithm = algId,
    md = "sha256",
    apu = baseutils.to_url64(producer),
    apv = baseutils.to_url64(consumer)
})

local expectedDerivedKey = cjson.decode("[86, 170, 141, 234, 248, 35, 109, 32, 92, 34, 40, 205, 113, 167, 16, 26]")
local expectedDerivedKeyByteString = cryptoLite.BAtoByteString(expectedDerivedKey)
logger.debugLog("derivedKey: " .. cjson.encode(cryptoLite.ByteStringtoBA(derivedKey)) .. " expectedDerivedKey: " .. cjson.encode(cryptoLite.ByteStringtoBA(expectedDerivedKeyByteString)))
local valid = (derivedKey == expectedDerivedKeyByteString)
local concatKDFText = "derivedKey: " .. cjson.encode(cryptoLite.ByteStringtoBA(derivedKey)) ..
    "\nexpectedDerivedKey: " .. cjson.encode(expectedDerivedKey) ..
    "\nEqual: " .. tostring(valid)
logger.debugLog("valid: " .. tostring(valid))
rspBody = rspBody .. createResultBlock("concatKDF test from http://tools.ietf.org/html/rfc7518#appendix-C", concatKDFText, valid)

-- RSA 2048 bit key generation
local rsaPublicKey, rsaPrivateKey = cryptoLite.generateRSAKeyPair(2048)
rspBody = rspBody .. createResultBlock("RSA Keypair (2048 bits)", rsaPrivateKey .. "\n" .. rsaPublicKey, true)

-- EC key generation
local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair()
rspBody = rspBody .. createResultBlock("ECDSA Keypair (prime256v1)", ecPrivateKey .. "\n" .. ecPublicKey, true)

-- symmetric key encryption and decryption
local symmetricKey = "mysecretkey"
local plainText = "mysecretdata"
local cipherText = cryptoLite.encryptSymmetric(plainText, symmetricKey)
local decryptedText = cryptoLite.decryptSymmetric(cipherText, symmetricKey)
local symmetricText = "symmetricKey: " .. symmetricKey .. "\nplainText: " .. plainText .. "\ncipherText: " .. cipherText .. "\ndecryptedText: " .. decryptedText
local valid = plainText == decryptedText
rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption", symmetricText, valid)

-- symmetric key encryption and decryption with AAD
-- requires AAD support
if aadSupport then
    local symmetricKey = "mysecretkey"
    local plainText = "mysecretdata"
    local aad = "myaad"
    local encryptOptions = {
        plaintext = plainText,
        key = symmetricKey,
        encryptionKeyAgreement = "dir",
        contentEncryptionAlgorithm = "A256GCM",
        additionalAuthenticatedData = aad
    }
    local success, encryptResults = pcall(cryptoLite.encrypt, encryptOptions)
    if success then
        local decryptOptions = {
            ciphertext = encryptResults.ciphertext,
            key = symmetricKey,
            encryptionKeyAgreement = "dir",
            contentEncryptionAlgorithm = "A256GCM",
            iv = encryptResults.iv,
            tag = encryptResults.tag,
            salt = encryptResults.salt,
            additionalAuthenticatedData = aad
        }
        local success, decryptedText = pcall(cryptoLite.decrypt, decryptOptions)
        if success then
            local symmetricText = "symmetricKey: " .. symmetricKey .. "\nplainText: " .. plainText .. "\ncipherText: " .. cipherText .. "\ndecryptedText: " .. decryptedText
            success = plainText == decryptedText
            rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with AAD", symmetricText, success)
        else
            rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with AAD", "Failed during decryption: " .. logger.dumpAsString(encryptResults), success)
        end
    else
        rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with AAD", "Failed during encryption: " .. logger.dumpAsString(encryptResults), success)
    end
else
    rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with AAD", "Feature unavailable in luaossl: additionalAuthenticatedData", false)
end

-- rsa encryption and decryption
plainText = "mysecretdata-rsa"
local success, cipherText = pcall(cryptoLite.encryptRSA, plainText, rsaPublicKey)
if success then
    local success, decryptedText = pcall(cryptoLite.decryptRSA, cipherText, rsaPrivateKey)
    if (success) then
        local rsaencText = "plainText: " .. plainText .. "\ncipherText: " .. cipherText .. "\ndecryptedText: " .. decryptedText
        local valid = decryptedText == plainText
        rspBody = rspBody .. createResultBlock("RSA key encryption/decryption", rsaencText, valid)
    else
        rspBody = rspBody .. createResultBlock("RSA key encryption/decryption", "Failed during decryptRSA: ", logger.dumpAsString(decryptedText), false)
    end
else
    rspBody = rspBody .. createResultBlock("RSA key encryption/decryption", "Failed during encryptRSA: ", logger.dumpAsString(cipherText), false)
end


-- ec-dh encryption and decryption - only available if key derivation feature is available
if ecDeriveSupport then
    plainText = "mysecretdata-ecdh"
    local success, cipherText = pcall(cryptoLite.encryptECDSA, plainText, ecPublicKey)
    if (success) then
        local success, decryptedText = pcall(cryptoLite.decryptECDSA, cipherText, ecPrivateKey)
        if (success) then
            local ecdhText = "plainText: " .. plainText .. "\n" .. "cipherText: " .. cipherText .. "\n" .. "decryptedText: " .. decryptedText
            local valid = decryptedText == plainText
            rspBody = rspBody .. createResultBlock("ECDH key encryption/decryption", ecdhText, valid)
        else
            rspBody = rspBody .. createResultBlock("RSA key encryption/decryption", "Failed during decryptECDSA: ", logger.dumpAsString(decryptedText), false)
        end
    else
        rspBody = rspBody .. createResultBlock("ECDH key encryption/decryption", "Failed during encryptECDSA: ", logger.dumpAsString(cipherText), false)
    end
else
    rspBody = rspBody .. createResultBlock("ECDH key encryption/decryption", "Feature unavailable in luaossl: ECDH", false)
end

-- JWT signature with HS256
local hmacSecret = "password"
rspBody = rspBody .. testJWTSignature("HS256", hmacSecret, hmacSecret)

-- JWT signature with RS256
rspBody = rspBody .. testJWTSignature("RS256", rsaPrivateKey, rsaPublicKey)


-- JWT signature with ES256
rspBody = rspBody .. testJWTSignature("RS256", ecPrivateKey, ecPublicKey)

--
-- Build a test based around the JWE example A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
--
local jweA1Str = ""
local jweA1Error = false
local joseHeader = '{"alg":"RSA-OAEP","enc":"A256GCM"}'
joseHeaderB64U = cryptoLite.base64URLEncode(joseHeader)
local testPlainText = "The true sign of intelligence is not knowledge but imagination."
local verifyPlaintextBytes = cjson.decode("[84, 104, 101, 32, 116, 114, 117, 101, 32, 115, 105, 103, 110, 32, 111, 102, 32, 105, 110, 116, 101, 108, 108, 105, 103, 101, 110, 99, 101, 32, 105, 115, 32, 110, 111, 116, 32, 107, 110, 111, 119, 108, 101, 100, 103, 101, 32, 98, 117, 116, 32, 105, 109, 97, 103, 105, 110, 97, 116, 105, 111, 110, 46]")
local testRSAPrivateKey = {
    kty = "RSA",
    n = "oahUIoWw0K0usKNuOR6H4wkf4oBUXHTxRvgb48E-BVvxkeDNjbC4he8rUWcJoZmds2h7M70imEVhRU5djINXtqllXI4DFqcI1DgjT9LewND8MW2Krf3Spsk_ZkoFnilakGygTwpZ3uesH-PFABNIUYpOiN15dsQRkgr0vEhxN92i2asbOenSZeyaxziK72UwxrrKoExv6kc5twXTq4h-QChLOln0_mtUZwfsRaMStPs6mS6XrgxnxbWhojf663tuEQueGC-FCMfra36C9knDFGzKsNa7LZK2djYgyD3JR_MB_4NUJW_TqOQtwHYbxevoJArm-L5StowjzGy-_bq6Gw",
    e = "AQAB",
    d = "kLdtIj6GbDks_ApCSTYQtelcNttlKiOyPzMrXHeI-yk1F7-kpDxY4-WY5NWV5KntaEeXS1j82E375xxhWMHXyvjYecPT9fpwR_M9gV8n9Hrh2anTpTD93Dt62ypW3yDsJzBnTnrYu1iwWRgBKrEYY46qAZIrA2xAwnm2X7uGR1hghkqDp0Vqj3kbSCz1XyfCs6_LehBwtxHIyh8Ripy40p24moOAbgxVw3rxT_vlt3UVe4WO3JkJOzlpUf-KTVI2Ptgm-dARxTEtE-id-4OJr0h-K-VFs3VSndVTIznSxfyrj8ILL6MG_Uv8YAu7VILSB3lOW085-4qE3DzgrTjgyQ",
    p = "1r52Xk46c-LsfB5P442p7atdPUrxQSy4mti_tZI3Mgf2EuFVbUoDBvaRQ-SWxkbkmoEzL7JXroSBjSrK3YIQgYdMgyAEPTPjXv_hI2_1eTSPVZfzL0lffNn03IXqWF5MDFuoUYE0hzb2vhrlN_rKrbfDIwUbTrjjgieRbwC6Cl0",
    q = "wLb35x7hmQWZsWJmB_vle87ihgZ19S8lBEROLIsZG4ayZVe9Hi9gDVCOBmUDdaDYVTSNx_8Fyw1YYa9XGrGnDew00J28cRUoeBB_jKI1oma0Orv1T9aXIWxKwd4gvxFImOWr3QRL9KEBRzk2RatUBnmDZJTIAfwTs0g68UZHvtc",
    dp = "ZK-YwE7diUh0qR1tR7w8WHtolDx3MZ_OTowiFvgfeQ3SiresXjm9gZ5KLhMXvo-uz-KUJWDxS5pFQ_M0evdo1dKiRTjVw_x4NyqyXPM5nULPkcpU827rnpZzAJKpdhWAgqrXGKAECQH0Xt4taznjnd_zVpAmZZq60WPMBMfKcuE",
    dq = "Dq0gfgJ1DdFGXiLvQEZnuKEN0UUmsJBxkjydc3j4ZYdBiMRAy86x0vHCjywcMlYYg4yoC4YZa9hNVcsjqA3FeiL19rk8g6Qn29Tt0cj8qqyFpz9vNDBUfCAiJVeESOjJDZPYHdHY8v1b-o-Z2X5tvLx-TCekf7oxyeKDUqKWjis",
    qi = "VIMpMYbPf47dT1w_zDUXfPimsSegnMOA1zTaX7aGk_8urY6R8-ZW1FxU7AlWAyLWybqq6t16VFd7hQd0y6flUK4SlOydB61gwanOsXGOAOv82cHq0E3eL4HrtZkUuKvnPrMnsUUFlfUdybVzxyjz9JF_XyaY14ardLSjf4L_FNY"
}
logger.debugLog("testRSAPrivateKey JWK: " .. cjson.encode(testRSAPrivateKey))

-- the public key is a subset of the private key
local testRSAPublicKey = {}
for k, v in pairs(testRSAPrivateKey) do
    if (k ~= "d" and k ~= "p" and k ~= "q" and k ~= "dp" and k ~= "dq" and k ~= "qi") then
        testRSAPublicKey[k] = v
    end
end
-- logger.debugLog("testRSAPublicKey: " .. logger.dumpAsString(testRSAPublicKey))
local testRSAPrivateKeyPEM = cryptoLite.jwkToPEM(testRSAPrivateKey)
logger.debugLog("testRSAPrivateKeyPEM: " .. testRSAPrivateKeyPEM)

local testRSAPublicKeyPEM = cryptoLite.jwkToPEM(testRSAPublicKey)
logger.debugLog("testRSAPublicKeyPEM: " .. testRSAPublicKeyPEM)


local testPlainTextHex = logger.toHexString(testPlainText)
local verifyPlaintextBytesHex = cryptoLite.BAtohex(verifyPlaintextBytes)
jweA1Error = not(testPlainTextHex == verifyPlaintextBytesHex)
jweA1Str = "testPlainTextHex == verifyPlaintextBytesHex : " .. tostring(testPlainTextHex == verifyPlaintextBytesHex)
logger.debugLog("testPlainTextHex == verifyPlaintextBytesHex : " .. tostring(testPlainTextHex == verifyPlaintextBytesHex))

if not jweA1Error then
    -- convert the CEK bytes to a byte string
    local testCEK = cjson.decode("[177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]")
    local testCEKByteString = cryptoLite.BAtoByteString(testCEK)
    local testCEKHex = cryptoLite.BAtohex(testCEK)
    logger.debugLog("testCEKHex: " .. testCEKHex)

    -- encrypt the CEK with the testRSAPublicKey
    local encryptedCEKB64U = cryptoLite.encryptRSA(testCEKByteString, testRSAPublicKeyPEM)
    local encryptedCEKHex = cryptoLite.ByteStringtohex(baseutils.from_url64(encryptedCEKB64U))
    logger.debugLog("encryptedCEKHex: " .. encryptedCEKHex)

    -- we cannot directly compare our encrypted CEK with the sample from the RFC as there is randomness to the encrypted output, but we can decrypt 
    -- the sample from the RFC and make sure that it equals our testCEK
    local verifyJWEEncryptedKey = cjson.decode("[56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203, 22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216, 82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214, 74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182, 13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228, 173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158, 89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138, 243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6, 41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126, 215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58, 63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98, 193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215, 206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216, 104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197, 89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219, 172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134, 117, 114, 135, 206]")
    local verifyJWEEncryptedKeyByteString = cryptoLite.BAtoByteString(verifyJWEEncryptedKey)
    local success, verifyJWEDecryptedKey = pcall(cryptoLite.decryptRSARaw, verifyJWEEncryptedKeyByteString, testRSAPrivateKeyPEM)

    if (success) then

        local verifyJWEDecryptedKeyHex = cryptoLite.ByteStringtohex(verifyJWEDecryptedKey)
        logger.debugLog("verifyJWEDecryptedKeyHex: " .. verifyJWEDecryptedKeyHex)
        logger.debugLog("testCEKHex == verifyJWEDecryptedKeyHex : " .. tostring(testCEKHex == verifyJWEDecryptedKeyHex))
        jweA1Error = not(testCEKHex == verifyJWEDecryptedKeyHex)
        jweA1Str = jweA1Str .. "\ntestCEKHex == verifyJWEDecryptedKeyHex : " .. tostring(testCEKHex == verifyJWEDecryptedKeyHex)

        if not jweA1Error then
            local testIV = cjson.decode("[227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]")
            local testIVByteString = cryptoLite.BAtoByteString(testIV)
            local testIVHex = cryptoLite.BAtohex(testIV)
            logger.debugLog("testIVHex: " .. testIVHex)

            local testAdditionalAuthenticatedData = cjson.decode('[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81]')
            local testAdditionalAuthenticatedDataHex = cryptoLite.BAtohex(testAdditionalAuthenticatedData)
            logger.debugLog("testAdditionalAuthenticatedDataHex: " .. testAdditionalAuthenticatedDataHex)

            local addtionalAuthenticatedData = cryptoLite.utf8toBA(joseHeaderB64U)
            local addtionalAuthenticatedDataHex = cryptoLite.BAtohex(addtionalAuthenticatedData)
            logger.debugLog("addtionalAuthenticatedDataHex: " .. addtionalAuthenticatedDataHex)
            logger.debugLog("testAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex : " .. tostring(testAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex))
            jweA1Error = not(testAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex)
            jweA1Str = jweA1Str .. "\ntestAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex : " .. tostring(testAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex)


            if not jweA1Error then
                local addtionalAuthenticatedDataByteString = cryptoLite.BAtoByteString(addtionalAuthenticatedData)

                local success, encryptResults = pcall(cryptoLite.encrypt, {
                    plaintext = testPlainText,
                    key = testCEKByteString,
                    encryptionKeyAgreement = "dir",
                    contentEncryptionAlgorithm = "A256GCM",
                    iv = testIVByteString,
                    additionalAuthenticatedData = addtionalAuthenticatedDataByteString})

                if (success) then
                    logger.debugLog("encryptResults: " .. logger.dumpAsString(encryptResults))

                    local jweString = joseHeaderB64U .. '.' .. encryptedCEKB64U .. '.' .. cryptoLite.base64URLEncode(encryptResults.iv) .. '.' .. cryptoLite.base64URLEncode(encryptResults.ciphertext) .. '.' .. cryptoLite.base64URLEncode(encryptResults.tag)
                    logger.debugLog("jweString: " .. jweString)

                    jweA1Str = jweA1Str .. "\njweString: " .. jweString
                else
                    jweA1Error = true
                    jweA1Str = jweA1Str .. "\ncryptoLite.encrypt failed: " .. logger.dumpAsString(encryptResults)
                end
            end
        end    
    else
        jweA1Error = true
        jweA1Str = jweA1Str .. "\ncryptoLite.decryptRSARaw failed: " .. logger.dumpAsString(verifyJWEDecryptedKey)
    end
end

if jweA1Str ~= nil then
    rspBody = rspBody .. createResultBlock("Test of JWE example A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1", jweA1Str, (not jweA1Error))
end

rspBody = rspBody .. "</body></html>"

HTTPResponse.setHeader("content-type", "text/html")
HTTPResponse.setBody(rspBody)
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)

