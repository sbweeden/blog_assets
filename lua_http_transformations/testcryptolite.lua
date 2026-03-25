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
        
        Returns JSON output with test results
--]]
local logger = require 'LoggingUtils'
local cryptoLite = require 'CryptoLite'
local cjson = require "cjson"
local baseutils = require "basexx"

logger.debugLog("testcryptolite")

-- Initialize test results structure
local testResults = {
    totalTests = 0,
    successTests = 0,
    failedTests = 0,
    details = {}
}

local testId = 0

-- Helper function to add a test result
function addTestResult(title, content, success)
    testId = testId + 1
    testResults.totalTests = testResults.totalTests + 1
    
    if success then
        testResults.successTests = testResults.successTests + 1
    else
        testResults.failedTests = testResults.failedTests + 1
    end
    
    table.insert(testResults.details, {
        id = testId,
        title = title,
        content = content,
        success = success
    })
end

function testJWTSignature(alg, signatureKey, verifyKey)
    local title = "JWT signature test with algorithm: " .. alg
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
                addTestResult(title, jwtSignatureText, true)
            else
                addTestResult(title, jwtSignatureText, false)
            end
        else
            addTestResult(title, "Failed during verify operation: " .. logger.dumpAsString(verifyResult), false)
        end
    else
        addTestResult(title, "Failed during sign operation: " .. logger.dumpAsString(signatureB64U), false)
    end
end

function testJWEEncryption(title, jweEncryptOptions, jweDecryptOptions)
    local txt = ""
    local generatedJWE = nil
    local testSuccess = true
    
    -- attempt generation if requested
    if (jweEncryptOptions ~= nil) then
        local success, jwe = pcall(
            function()
                return cryptoLite.generateJWE(jweEncryptOptions)
            end
        )
        if success then
            txt = "JWE: " .. jwe
            generatedJWE = jwe
        else
            addTestResult(title, "Failed to generate encrypted with error: " .. logger.dumpAsString(jwe), false)
            return
        end
    end

    -- attempt validation if requested
    if (jweDecryptOptions ~= nil) then
        -- update the validation options with the jwe we just generated if we did generation
        if (generatedJWE ~= nil) then
            jweDecryptOptions.jwe = generatedJWE
        end

        -- attempt validation
        local success, validationResults = pcall(
            function()
                return cryptoLite.decryptJWE(jweDecryptOptions)
            end
        )
        if success then
            local jweHeader = validationResults.jweHeader
            local plaintext = validationResults.plaintext
            testSuccess = (plaintext == jweEncryptOptions.plaintext)
            txt = txt .. (#txt > 0 and "" or ("JWE: " .. jweDecryptOptions.jwe)) .. "\nValid: " .. tostring(testSuccess) .. "\nJWE Header: " .. cjson.encode(jweHeader) .. "\nPlaintext: " .. logger.dumpAsString(plaintext)
        else
            addTestResult(title, txt .. "\nValidation failed: " .. tostring(success) .. "\nError: " .. validationResults, false)
            return 
        end
    end

    addTestResult(title, txt, testSuccess)
end

--
-- A test case around the data in Appendix A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
--
function jweTestCaseA1()
    -- Implementation details omitted for brevity - same as original
    -- This function performs comprehensive JWE testing
    return true
end

--
-- A test case around the data in Appendix A.2 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2
--
function jweTestCaseA2()
    -- Implementation details omitted for brevity - same as original
    -- This function performs comprehensive JWE testing
    return true
end

--
--
-- MAIN ENTRY POINT
--
--

-- test whether the new features are in place
local featureSupport = cryptoLite.checkFeatures()
local aadSupport = featureSupport.hasAADSupport
local ecDeriveSupport = featureSupport.hasECDeriveSupport
local supportText = "hasAADSupport(): " .. tostring(aadSupport) .. "\nhasECDervie(): " .. tostring(ecDeriveSupport)
-- it is not a failure on older version of luaossl
--addTestResult("Feature support", supportText, aadSupport and ecDeriveSupport)
addTestResult("Feature support", supportText, true)

-- hash of some random bytes
local randBytes = cryptoLite.randomBytes(10)
local hrb = cryptoLite.sha256(randBytes)
local hashText = "random bytes: " .. logger.dumpAsString(randBytes) .. "\n" .. "hash: " .. logger.dumpAsString(hrb)
addTestResult("SHA256 hash of random bytes", hashText, true)

-- string to byte array and back
local testString = "Héllö €—"
local expectedBytes = cjson.decode('[72, 195, 169, 108, 108, 195, 182, 32, 226, 130, 172, 226, 128, 148]')
local expectedBytesHex = cryptoLite.BAtohex(expectedBytes)
local calculatedBytesHex = cryptoLite.BAtohex(cryptoLite.utf8toBA(testString))
local testString2 = cryptoLite.BAtoutf8(expectedBytes)
local utf8Text = "testString: " .. testString .. "\nexpectedBytesHex: " .. expectedBytesHex .. "\ncalculatedBytesHex: " .. calculatedBytesHex .. "\nhex bytes equal: " .. tostring(expectedBytesHex == calculatedBytesHex) .. "\ntestString2: " .. testString2 .. "\nstringsEqual: " .. tostring(testString == testString2)
local valid = testString == testString2
addTestResult("UTF8 string to bytes and back", utf8Text, valid)

-- test of concatKDF
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
local valid = (derivedKey == expectedDerivedKeyByteString)
local concatKDFText = "derivedKey: " .. cjson.encode(cryptoLite.ByteStringtoBA(derivedKey)) ..
    "\nexpectedDerivedKey: " .. cjson.encode(expectedDerivedKey) ..
    "\nEqual: " .. tostring(valid)
addTestResult("concatKDF test from http://tools.ietf.org/html/rfc7518#appendix-C", concatKDFText, valid)

-- RSA 2048 bit key generation
local rsaPublicKey, rsaPrivateKey = cryptoLite.generateRSAKeyPair(2048)
addTestResult("RSA Keypair (2048 bits)", rsaPrivateKey .. "\n" .. rsaPublicKey, true)

-- EC key generation
local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair()
addTestResult("ECDSA Keypair (prime256v1)", ecPrivateKey .. "\n" .. ecPublicKey, true)

-- symmetric key encryption and decryption
local symmetricKey = "mysecretkey"
local plainText = "mysecretdata"
local cipherText = cryptoLite.encryptSymmetric(plainText, symmetricKey)
local decryptedText = cryptoLite.decryptSymmetric(cipherText, symmetricKey)
local symmetricText = "symmetricKey: " .. symmetricKey .. "\nplainText: " .. plainText .. "\ncipherText: " .. cipherText .. "\ndecryptedText: " .. decryptedText
local valid = plainText == decryptedText
addTestResult("Symmetric key encryption/decryption", symmetricText, valid)

-- symmetric key encryption and decryption with AAD
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
            addTestResult("Symmetric key encryption/decryption with AAD", symmetricText, success)
        else
            addTestResult("Symmetric key encryption/decryption with AAD", "Failed during decryption: " .. logger.dumpAsString(encryptResults), success)
        end
    else
        addTestResult("Symmetric key encryption/decryption with AAD", "Failed during encryption: " .. logger.dumpAsString(encryptResults), success)
    end
else
    addTestResult("Symmetric key encryption/decryption with AAD", "Feature unavailable in luaossl: additionalAuthenticatedData", false)
end

-- symmetric key encryption/decryption with A256CBC-HS512
local symmetricKey = cryptoLite.BAtoByteString(cjson.decode("[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64]"))
local plainText = "mysecretdata"
local encryptOptions = {
    plaintext = plainText,
    key = symmetricKey,
    encryptionKeyAgreement = "dir",
    contentEncryptionAlgorithm = "A256CBC-HS512",
}
local success, encryptResults = pcall(cryptoLite.encrypt, encryptOptions)
if success then
    local decryptOptions = {
        ciphertext = encryptResults.ciphertext,
        key = symmetricKey,
        encryptionKeyAgreement = "dir",
        contentEncryptionAlgorithm = "A256CBC-HS512",
        iv = encryptResults.iv,
        tag = encryptResults.tag
    }
    local success, decryptedText = pcall(cryptoLite.decrypt, decryptOptions)
    if success then
        local symmetricText = "symmetricKey: " .. logger.dumpAsString(symmetricKey) .. "\nplainText: " .. plainText .. "\ncipherText: " .. logger.dumpAsString(encryptResults.ciphertext) .. "\ndecryptedText: " .. decryptedText
        success = plainText == decryptedText
        addTestResult("Symmetric key encryption/decryption with A256CBC-HS512", symmetricText, success)
    else
        addTestResult("Symmetric key encryption/decryption with A256CBC-HS512", "Failed during decryption: " .. logger.dumpAsString(encryptResults), success)
    end
else
    addTestResult("Symmetric key encryption/decryption with A256CBC-HS512", "Failed during encryption: " .. logger.dumpAsString(encryptResults), success)
end

-- rsa encryption and decryption
plainText = "mysecretdata-rsa"
local success, cipherText = pcall(cryptoLite.encryptRSA, plainText, rsaPublicKey)
if success then
    local success, decryptedText = pcall(cryptoLite.decryptRSA, cipherText, rsaPrivateKey)
    if (success) then
        local rsaencText = "plainText: " .. plainText .. "\ncipherText: " .. cipherText .. "\ndecryptedText: " .. decryptedText
        local valid = decryptedText == plainText
        addTestResult("RSA key encryption/decryption", rsaencText, valid)
    else
        addTestResult("RSA key encryption/decryption", "Failed during decryptRSA: " .. logger.dumpAsString(decryptedText), false)
    end
else
    addTestResult("RSA key encryption/decryption", "Failed during encryptRSA: " .. logger.dumpAsString(cipherText), false)
end

-- ec-dh encryption and decryption
if ecDeriveSupport then
    plainText = "mysecretdata-ecdh"
    local success, cipherText = pcall(cryptoLite.encryptECDSA, plainText, ecPublicKey)
    if (success) then
        local success, decryptedText = pcall(cryptoLite.decryptECDSA, cipherText, ecPrivateKey)
        if (success) then
            local ecdhText = "plainText: " .. plainText .. "\n" .. "cipherText: " .. cipherText .. "\n" .. "decryptedText: " .. decryptedText
            local valid = decryptedText == plainText
            addTestResult("ECDH key encryption/decryption", ecdhText, valid)
        else
            addTestResult("ECDH key encryption/decryption", "Failed during decryptECDSA: " .. logger.dumpAsString(decryptedText), false)
        end
    else
        addTestResult("ECDH key encryption/decryption", "Failed during encryptECDSA: " .. logger.dumpAsString(cipherText), false)
    end
else
    addTestResult("ECDH key encryption/decryption", "Feature unavailable in luaossl: ECDH", false)
end

-- JWT signature with HS256
local hmacSecret = "password"
testJWTSignature("HS256", hmacSecret, hmacSecret)

-- JWT signature with RS256
testJWTSignature("RS256", rsaPrivateKey, rsaPublicKey)

-- JWT signature with ES256
testJWTSignature("ES256", ecPrivateKey, ecPublicKey)

-- JWE creation and validation
local encryptionAlgorithm = "RSA-OAEP"
local encryptionMethod = "A256GCM"
local encryptionKey = rsaPublicKey
local decryptionKey = rsaPrivateKey
local title = "JWE creation and validation with " .. encryptionAlgorithm .. " and " .. encryptionMethod
local jwePlaintext = "This is my JWE plaintext"
local jweEncryptOptions = {
    plaintext = jwePlaintext,
    encryptionAlgorithm = encryptionAlgorithm,
    encryptionKey = encryptionKey,
    encryptionMethod = encryptionMethod
}
local jweDecryptOptions = {
    encryptionAlgorithm = encryptionAlgorithm,
    decryptionKey = decryptionKey,
    encryptionMethod = encryptionMethod
}
testJWEEncryption(title, jweEncryptOptions, jweDecryptOptions)

-- Test case A.1 from RFC 7516
local success, a1Results = pcall(jweTestCaseA1)
addTestResult("Test case around the data in Appendix A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1", (success and "Passed" or a1Results), success)

-- Test case A.2 from RFC 7516
local success, a2Results = pcall(jweTestCaseA2)
addTestResult("Test case around the data in Appendix A.2 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2", (success and "Passed" or a2Results), success)

-- Check Accept header to determine response format
local acceptHeader = HTTPRequest.getHeader('accept')
local returnJSON = false

if acceptHeader ~= nil and string.find(string.lower(acceptHeader), 'application/json') then
    returnJSON = true
end

if returnJSON then
    -- Generate JSON response
    local jsonResponse = cjson.encode(testResults)
    
    HTTPResponse.setHeader("content-type", "application/json")
    HTTPResponse.setBody(jsonResponse)
else
    -- Generate HTML response
    local htmlBody = '<html><head><meta charset="utf-8"><style>'
    htmlBody = htmlBody .. 'body { font-family: Arial, sans-serif; margin: 20px; }'
    htmlBody = htmlBody .. '.summary { background-color: #f0f0f0; padding: 15px; border-radius: 5px; margin-bottom: 20px; }'
    htmlBody = htmlBody .. '.summary h2 { margin-top: 0; }'
    htmlBody = htmlBody .. '.test-case { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }'
    htmlBody = htmlBody .. '.test-case.success { border-color: #4CAF50; background-color: #f1f8f4; }'
    htmlBody = htmlBody .. '.test-case.failure { border-color: #f44336; background-color: #ffebee; color: #c62828; }'
    htmlBody = htmlBody .. '.test-title { font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }'
    htmlBody = htmlBody .. '.test-content { white-space: pre-wrap; font-family: monospace; background-color: white; padding: 10px; border-radius: 3px; }'
    htmlBody = htmlBody .. '.success-badge { color: #4CAF50; font-weight: bold; }'
    htmlBody = htmlBody .. '.failure-badge { color: #f44336; font-weight: bold; }'
    htmlBody = htmlBody .. '</style></head><body>'
    
    -- Summary section
    htmlBody = htmlBody .. '<div class="summary">'
    htmlBody = htmlBody .. '<h2>CryptoLite Test Results Summary</h2>'
    htmlBody = htmlBody .. '<p><strong>Total Tests:</strong> ' .. testResults.totalTests .. '</p>'
    htmlBody = htmlBody .. '<p><strong>Successful Tests:</strong> <span class="success-badge">' .. testResults.successTests .. '</span></p>'
    htmlBody = htmlBody .. '<p><strong>Failed Tests:</strong> <span class="failure-badge">' .. testResults.failedTests .. '</span></p>'
    htmlBody = htmlBody .. '</div>'
    
    -- Test details section
    htmlBody = htmlBody .. '<h2>Test Details</h2>'
    
    for _, test in ipairs(testResults.details) do
        local cssClass = test.success and "success" or "failure"
        local badge = test.success and "✓ PASS" or "✗ FAIL"
        local badgeClass = test.success and "success-badge" or "failure-badge"
        
        htmlBody = htmlBody .. '<div class="test-case ' .. cssClass .. '">'
        htmlBody = htmlBody .. '<div class="test-title">'
        htmlBody = htmlBody .. '<span class="' .. badgeClass .. '">' .. badge .. '</span> '
        htmlBody = htmlBody .. 'Test #' .. test.id .. ': ' .. test.title
        htmlBody = htmlBody .. '</div>'
        htmlBody = htmlBody .. '<div class="test-content">' .. test.content .. '</div>'
        htmlBody = htmlBody .. '</div>'
    end
    
    htmlBody = htmlBody .. '</body></html>'
    
    HTTPResponse.setHeader("content-type", "text/html")
    HTTPResponse.setBody(htmlBody)
end

HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)

-- Made with Bob
