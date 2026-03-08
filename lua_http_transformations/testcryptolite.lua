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

logger.debugLog("testcryptolite")

local rspBody = '<html><head><meta charset="utf-8"></head><body>'


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
                return preBlockWithTitle(title, jwtSignatureText)
            else
                return errorBlockWithTitle(title .. " FAILED", jwtSignatureText)
            end
        else
            return errorBlockWithTitle(title .. " FAILED", "Failed during verify operation: " .. logger.dumpAsString(verifyResult))
        end
    else
        return errorBlockWithTitle(title .. " FAILED", "Failed during sign operation: " .. logger.dumpAsString(signatureB64U))
    end
end

function testJWEEncryption(title, jweEncryptOptions, jweDecryptOptions)
    local txt = ""
    local generatedJWE = nil
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
            rspBody = rspBody .. errorBlockWithTitle(title, "Failed to generate encrypted with error: " .. logger.dumpAsString(jwe))
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
            success = (plaintext == jweEncryptOptions.plaintext)
            txt = txt .. (#txt > 0 and "" or ("JWE: " .. jweDecryptOptions.jwe)) .. "\nValid: " .. tostring(success) .. "\nJWE Header: " .. cjson.encode(jweHeader) .. "\nPlaintext: " .. logger.dumpAsString(plaintext)
        else
            rspBody = rspBody .. errorBlockWithTitle(title, txt .. "\nValidation failed: " .. tostring(success) .. "\nError: " .. validationResults)
            return 
        end
    end

    rspBody = rspBody .. preBlockWithTitle(title, txt)
end

--
-- A test case around the data in Appendix A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
--
function jweTestCaseA1()
    local jweA1Str = ""
    local joseHeaderStr = '{"alg":"RSA-OAEP","enc":"A256GCM"}'
    joseHeaderB64U = cryptoLite.base64URLEncode(joseHeaderStr)
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

    -- the public key is a subset of the private key
    local testRSAPublicKey = {}
    for k, v in pairs(testRSAPrivateKey) do
        if (k ~= "d" and k ~= "p" and k ~= "q" and k ~= "dp" and k ~= "dq" and k ~= "qi") then
            testRSAPublicKey[k] = v
        end
    end

    local testRSAPrivateKeyPEM = cryptoLite.jwkToPEM(testRSAPrivateKey)
    local testRSAPublicKeyPEM = cryptoLite.jwkToPEM(testRSAPublicKey)

    local testPlainTextHex = logger.toHexString(testPlainText)
    local verifyPlaintextBytesHex = cryptoLite.BAtohex(verifyPlaintextBytes)
    if not(testPlainTextHex == verifyPlaintextBytesHex) then
        error("testPlainTextHex("..testPlainTextHex..") not equal to verifyPlaintextBytesHex("..verifyPlaintextBytesHex..")")
    end

    -- convert the CEK bytes to a byte string
    local testCEK = cjson.decode("[177, 161, 244, 128, 84, 143, 225, 115, 63, 180, 3, 255, 107, 154, 212, 246, 138, 7, 110, 91, 112, 46, 34, 105, 47, 130, 203, 46, 122, 234, 64, 252]")
    local testCEKByteString = cryptoLite.BAtoByteString(testCEK)
    local testCEKHex = cryptoLite.BAtohex(testCEK)

    -- encrypt the CEK with the testRSAPublicKey
    local encryptedCEK = cryptoLite.encryptRSARaw(testCEKByteString, testRSAPublicKeyPEM, "RSA_PKCS1_OAEP_PADDING")
    local encryptedCEKHex = cryptoLite.ByteStringtohex(encryptedCEK)

    -- we cannot directly compare our encrypted CEK with the sample from the RFC as there is randomness to the encrypted output, but we can decrypt 
    -- the sample from the RFC and make sure that it equals our testCEK, and we can do the same for our encrypted CEK
    local verifyJWEEncryptedKey = cjson.decode("[56, 163, 154, 192, 58, 53, 222, 4, 105, 218, 136, 218, 29, 94, 203, 22, 150, 92, 129, 94, 211, 232, 53, 89, 41, 60, 138, 56, 196, 216, 82, 98, 168, 76, 37, 73, 70, 7, 36, 8, 191, 100, 136, 196, 244, 220, 145, 158, 138, 155, 4, 117, 141, 230, 199, 247, 173, 45, 182, 214, 74, 177, 107, 211, 153, 11, 205, 196, 171, 226, 162, 128, 171, 182, 13, 237, 239, 99, 193, 4, 91, 219, 121, 223, 107, 167, 61, 119, 228, 173, 156, 137, 134, 200, 80, 219, 74, 253, 56, 185, 91, 177, 34, 158, 89, 154, 205, 96, 55, 18, 138, 43, 96, 218, 215, 128, 124, 75, 138, 243, 85, 25, 109, 117, 140, 26, 155, 249, 67, 167, 149, 231, 100, 6, 41, 65, 214, 251, 232, 87, 72, 40, 182, 149, 154, 168, 31, 193, 126, 215, 89, 28, 111, 219, 125, 182, 139, 235, 195, 197, 23, 234, 55, 58, 63, 180, 68, 202, 206, 149, 75, 205, 248, 176, 67, 39, 178, 60, 98, 193, 32, 238, 122, 96, 158, 222, 57, 183, 111, 210, 55, 188, 215, 206, 180, 166, 150, 166, 106, 250, 55, 229, 72, 40, 69, 214, 216, 104, 23, 40, 135, 212, 28, 127, 41, 80, 175, 174, 168, 115, 171, 197, 89, 116, 92, 103, 246, 83, 216, 182, 176, 84, 37, 147, 35, 45, 219, 172, 99, 226, 233, 73, 37, 124, 42, 72, 49, 242, 35, 127, 184, 134, 117, 114, 135, 206]")
    local verifyJWEEncryptedKeyByteString = cryptoLite.BAtoByteString(verifyJWEEncryptedKey)
    local success, verifyJWEDecryptedKey = pcall(cryptoLite.decryptRSARaw, verifyJWEEncryptedKeyByteString, testRSAPrivateKeyPEM, "RSA_PKCS1_OAEP_PADDING")
    if not success then
        error("cryptoLite.decryptRSARaw failed on the verifyJWEEncryptedKey: " .. logger.dumpAsString(verifyJWEDecryptedKey))
    end
    local verifyJWEDecryptedKeyHex = cryptoLite.ByteStringtohex(verifyJWEDecryptedKey)
    if not (testCEKHex == verifyJWEDecryptedKeyHex) then
        error("testCEKHex("..testCEKHex..") not equal to verifyJWEDecryptedKeyHex("..verifyJWEDecryptedKeyHex..")")
    end

    -- same test with the encrypted key that we produced
    local success, jweDecryptedKey = pcall(cryptoLite.decryptRSARaw, encryptedCEK, testRSAPrivateKeyPEM, "RSA_PKCS1_OAEP_PADDING")
    if not success then
        error("cryptoLite.decryptRSARaw failed on the encryptedCEK: " .. logger.dumpAsString(jweDecryptedKey))
    end
    local jweDecryptedKeyHex = cryptoLite.ByteStringtohex(jweDecryptedKey)
    if not (testCEKHex == jweDecryptedKeyHex) then
        error("testCEKHex("..testCEKHex..") not equal to jweDecryptedKeyHex("..jweDecryptedKeyHex..")")
    end

    -- now use the example IV and AAD  along with the CEK to perform content encryption
    local testIV = cjson.decode("[227, 197, 117, 252, 2, 219, 233, 68, 180, 225, 77, 219]")
    local testIVByteString = cryptoLite.BAtoByteString(testIV)
    local testIVHex = cryptoLite.BAtohex(testIV)

    local testAdditionalAuthenticatedData = cjson.decode('[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69, 116, 84, 48, 70, 70, 85, 67, 73, 115, 73, 109, 86, 117, 89, 121, 73, 54, 73, 107, 69, 121, 78, 84, 90, 72, 81, 48, 48, 105, 102, 81]')
    local testAdditionalAuthenticatedDataHex = cryptoLite.BAtohex(testAdditionalAuthenticatedData)

    local addtionalAuthenticatedData = cryptoLite.utf8toBA(joseHeaderB64U)
    local addtionalAuthenticatedDataHex = cryptoLite.BAtohex(addtionalAuthenticatedData)

    -- this should not ever happen
    if not (testAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex) then
        error("testAdditionalAuthenticatedDataHex("..testAdditionalAuthenticatedDataHex..") not equal to addtionalAuthenticatedDataHex("..addtionalAuthenticatedDataHex..")")
    end

    local addtionalAuthenticatedDataByteString = cryptoLite.BAtoByteString(addtionalAuthenticatedData)

    -- content encryption with the symmetric CEK
    local success, encryptResults = pcall(cryptoLite.encrypt, {
        plaintext = testPlainText,
        key = testCEKByteString,
        encryptionKeyAgreement = "dir",
        contentEncryptionAlgorithm = "A256GCM",
        iv = testIVByteString,
        additionalAuthenticatedData = addtionalAuthenticatedDataByteString})

    if not success then
        error("cryptoLite.encrypt failed: " .. logger.dumpAsString(encryptResults))
    end

    -- compare actual ciphertext against expected
    local testCiphertext = cjson.decode('[229, 236, 166, 241, 53, 191, 115, 196, 174, 43, 73, 109, 39, 122, 233, 96, 140, 206, 120, 52, 51, 237, 48, 11, 190, 219, 186, 80, 111, 104, 50, 142, 47, 167, 59, 61, 181, 127, 196, 21, 40, 82, 242, 32, 123, 143, 168, 226, 73, 216, 176, 144, 138, 247, 106, 60, 16, 205, 160, 109, 64, 63, 192]')
    local testCiphertextHex = cryptoLite.BAtohex(testCiphertext)
    local ciphertextHex = cryptoLite.ByteStringtohex(encryptResults.ciphertext)

    if not(testCiphertextHex == ciphertextHex) then
        error("testCiphertextHex("..testCiphertextHex..") not equal to ciphertextHex("..ciphertextHex..")")
    end

    -- compare actual tag against expected
    local testTag = cjson.decode('[92, 80, 104, 49, 133, 25, 161, 215, 173, 101, 219, 211, 136, 91, 210, 145]')
    local testTagHex = cryptoLite.BAtohex(testTag)
    local tagHex = cryptoLite.ByteStringtohex(encryptResults.tag)
    if not(testTagHex == tagHex) then
        error("testTagHex("..testTagHex..") not equal to tagHex("..tagHex..")")
    end

    local jweString = joseHeaderB64U .. '.' .. cryptoLite.base64URLEncode(encryptedCEK) .. '.' .. cryptoLite.base64URLEncode(encryptResults.iv) .. '.' .. cryptoLite.base64URLEncode(encryptResults.ciphertext) .. '.' .. cryptoLite.base64URLEncode(encryptResults.tag)

    -- we cannot compare our actual jweString against test JWE because the encrypted CEK is non-deterministic but what we can do is decrypt the test JWE
    -- and make sure we get the same plaintext
    local testJWE = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGeipsEdY3mx_etLbbWSrFr05kLzcSr4qKAq7YN7e9jwQRb23nfa6c9d-StnImGyFDbSv04uVuxIp5Zms1gNxKKK2Da14B8S4rzVRltdYwam_lDp5XnZAYpQdb76FdIKLaVmqgfwX7XWRxv2322i-vDxRfqNzo_tETKzpVLzfiwQyeyPGLBIO56YJ7eObdv0je81860ppamavo35UgoRdbYaBcoh9QcfylQr66oc6vFWXRcZ_ZT2LawVCWTIy3brGPi6UklfCpIMfIjf7iGdXKHzg.48V1_ALb6US04U3b.5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6jiSdiwkIr3ajwQzaBtQD_A.XFBoMYUZodetZdvTiFvSkQ"
    local success, decryptedTestJWEResults = pcall(
        cryptoLite.decryptJWE, 
        {
            jwe = testJWE,
            encryptionAlgorithm = "RSA-OAEP",
            decryptionKey = testRSAPrivateKeyPEM,
            encryptionMethod = "A256GCM"
        }
    )

    if not success then
        error("Unable to decrypt the example JWE string")
    end

    -- check that the decrypted plaintext is what we expect, as are the JWE header components for enc and alg
    local joseHeader = cjson.decode(joseHeaderStr)
    if not decryptedTestJWEResults.jweHeader.enc == joseHeader.enc then
        error("The decrypted testJWE did not have the expected encryption method")
    end
    if not decryptedTestJWEResults.jweHeader.alg == joseHeader.alg then
        error("The decrypted testJWE did not have the expected encryption algorithm")
    end

    if not (testPlainText == decryptedTestJWEResults.plaintext) then
        error("The decrypted testJWE did not match the test plaintext")
    end

    -- Wow, everthing passed!
    return true
end


--
-- A test case around the data in Appendix A.2 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2
--
function jweTestCaseA2()
    local jweA2Str = ""
    local joseHeaderStr = '{"alg":"RSA1_5","enc":"A128CBC-HS256"}'
    joseHeaderB64U = cryptoLite.base64URLEncode(joseHeaderStr)
    local testPlainText = "Live long and prosper."
    local verifyPlaintextBytes = cjson.decode("[76, 105, 118, 101, 32, 108, 111, 110, 103, 32, 97, 110, 100, 32, 112, 114, 111, 115, 112, 101, 114, 46]")
    local testRSAPrivateKey = {
        kty = "RSA",
        n = "sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw",
        e = "AQAB",
        d = "VFCWOqXr8nvZNyaaJLXdnNPXZKRaWCjkU5Q2egQQpTBMwhprMzWzpR8Sxq1OPThh_J6MUD8Z35wky9b8eEO0pwNS8xlh1lOFRRBoNqDIKVOku0aZb-rynq8cxjDTLZQ6Fz7jSjR1Klop-YKaUHc9GsEofQqYruPhzSA-QgajZGPbE_0ZaVDJHfyd7UUBUKunFMScbflYAAOYJqVIVwaYR5zWEEceUjNnTNo_CVSj-VvXLO5VZfCUAVLgW4dpf1SrtZjSt34YLsRarSb127reG_DUwg9Ch-KyvjT1SkHgUWRVGcyly7uvVGRSDwsXypdrNinPA4jlhoNdizK2zF2CWQ",
        p = "9gY2w6I6S6L0juEKsbeDAwpd9WMfgqFoeA9vEyEUuk4kLwBKcoe1x4HG68ik918hdDSE9vDQSccA3xXHOAFOPJ8R9EeIAbTi1VwBYnbTp87X-xcPWlEPkrdoUKW60tgs1aNd_Nnc9LEVVPMS390zbFxt8TN_biaBgelNgbC95sM",
        q = "uKlCKvKv_ZJMVcdIs5vVSU_6cPtYI1ljWytExV_skstvRSNi9r66jdd9-yBhVfuG4shsp2j7rGnIio901RBeHo6TPKWVVykPu1iYhQXw1jIABfw-MVsN-3bQ76WLdt2SDxsHs7q7zPyUyHXmps7ycZ5c72wGkUwNOjYelmkiNS0",
        dp = "w0kZbV63cVRvVX6yk3C8cMxo2qCM4Y8nsq1lmMSYhG4EcL6FWbX5h9yuvngs4iLEFk6eALoUS4vIWEwcL4txw9LsWH_zKI-hwoReoP77cOdSL4AVcraHawlkpyd2TWjE5evgbhWtOxnZee3cXJBkAi64Ik6jZxbvk-RR3pEhnCs",
        dq = "o_8V14SezckO6CNLKs_btPdFiO9_kC1DsuUTd2LAfIIVeMZ7jn1Gus_Ff7B7IVx3p5KuBGOVF8L-qifLb6nQnLysgHDh132NDioZkhH7mI7hPG-PYE_odApKdnqECHWw0J-F0JWnUd6D2B_1TvF9mXA2Qx-iGYn8OVV1Bsmp6qU",
        qi = "eNho5yRBEBxhGBtQRww9QirZsB66TrfFReG_CcteI1aCneT0ELGhYlRlCtUkTRclIfuEPmNsNDPbLoLqqCVznFbvdB7x-Tl-m0l_eFTj2KiqwGqE9PZB9nNTwMVvH3VRRSLWACvPnSiwP8N5Usy-WRXS-V7TbpxIhvepTfE0NNo"
    }

    -- the public key is a subset of the private key
    local testRSAPublicKey = {}
    for k, v in pairs(testRSAPrivateKey) do
        if (k ~= "d" and k ~= "p" and k ~= "q" and k ~= "dp" and k ~= "dq" and k ~= "qi") then
            testRSAPublicKey[k] = v
        end
    end
    local testRSAPrivateKeyPEM = cryptoLite.jwkToPEM(testRSAPrivateKey)
    local testRSAPublicKeyPEM = cryptoLite.jwkToPEM(testRSAPublicKey)

    local testPlainTextHex = logger.toHexString(testPlainText)
    local verifyPlaintextBytesHex = cryptoLite.BAtohex(verifyPlaintextBytes)
    if not(testPlainTextHex == verifyPlaintextBytesHex) then
        error("testPlainTextHex("..testPlainTextHex..") not equal to verifyPlaintextBytesHex("..verifyPlaintextBytesHex..")")
    end

    -- convert the CEK bytes to a byte string
    local testCEK = cjson.decode("[4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106, 206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156, 44, 207]")
    local testCEKByteString = cryptoLite.BAtoByteString(testCEK)
    local testCEKHex = cryptoLite.BAtohex(testCEK)

    -- encrypt the CEK with the testRSAPublicKey
    local encryptedCEK = cryptoLite.encryptRSARaw(testCEKByteString, testRSAPublicKeyPEM, "RSA_PKCS1_PADDING")
    local encryptedCEKHex = cryptoLite.ByteStringtohex(encryptedCEK)

    -- we cannot directly compare our encrypted CEK with the sample from the RFC as there is randomness to the encrypted output, but we can decrypt 
    -- the sample from the RFC and make sure that it equals our testCEK
    local verifyJWEEncryptedKey = cjson.decode("[80, 104, 72, 58, 11, 130, 236, 139, 132, 189, 255, 205, 61, 86, 151, 176, 99, 40, 44, 233, 176, 189, 205, 70, 202, 169, 72, 40, 226, 181, 156, 223, 120, 156, 115, 232, 150, 209, 145, 133, 104, 112, 237, 156, 116, 250, 65, 102, 212, 210, 103, 240, 177, 61, 93, 40, 71, 231, 223, 226, 240, 157, 15, 31, 150, 89, 200, 215, 198, 203, 108, 70, 117, 66, 212, 238, 193, 205, 23, 161, 169, 218, 243, 203, 128, 214, 127, 253, 215, 139, 43, 17, 135, 103, 179, 220, 28, 2, 212, 206, 131, 158, 128, 66, 62, 240, 78, 186, 141, 125, 132, 227, 60, 137, 43, 31, 152, 199, 54, 72, 34, 212, 115, 11, 152, 101, 70, 42, 219, 233, 142, 66, 151, 250, 126, 146, 141, 216, 190, 73, 50, 177, 146, 5, 52, 247, 28, 197, 21, 59, 170, 247, 181, 89, 131, 241, 169, 182, 246, 99, 15, 36, 102, 166, 182, 172, 197, 136, 230, 120, 60, 58, 219, 243, 149, 94, 222, 150, 154, 194, 110, 227, 225, 112, 39, 89, 233, 112, 207, 211, 241, 124, 174, 69, 221, 179, 107, 196, 225, 127, 167, 112, 226, 12, 242, 16, 24, 28, 120, 182, 244, 213, 244, 153, 194, 162, 69, 160, 244, 248, 63, 165, 141, 4, 207, 249, 193, 79, 131, 0, 169, 233, 127, 167, 101, 151, 125, 56, 112, 111, 248, 29, 232, 90, 29, 147, 110, 169, 146, 114, 165, 204, 71, 136, 41, 252]")
    local verifyJWEEncryptedKeyByteString = cryptoLite.BAtoByteString(verifyJWEEncryptedKey)
    local success, verifyJWEDecryptedKey = pcall(cryptoLite.decryptRSARaw, verifyJWEEncryptedKeyByteString, testRSAPrivateKeyPEM, "RSA_PKCS1_PADDING")
    if not success then
        error("cryptoLite.decryptRSARaw failed on the verifyJWEEncryptedKey: " .. logger.dumpAsString(verifyJWEDecryptedKey))
    end
    local verifyJWEDecryptedKeyHex = cryptoLite.ByteStringtohex(verifyJWEDecryptedKey)
    if not (testCEKHex == verifyJWEDecryptedKeyHex) then
        error("testCEKHex("..testCEKHex..") not equal to verifyJWEDecryptedKeyHex("..verifyJWEDecryptedKeyHex..")")
    end

    -- same test with the encrypted key that we produced
    local success, jweDecryptedKey = pcall(cryptoLite.decryptRSARaw, encryptedCEK, testRSAPrivateKeyPEM, "RSA_PKCS1_PADDING")
    if not success then
        error("cryptoLite.decryptRSARaw failed on the encryptedCEK: " .. logger.dumpAsString(jweDecryptedKey))
    end
    local jweDecryptedKeyHex = cryptoLite.ByteStringtohex(jweDecryptedKey)
    if not (testCEKHex == jweDecryptedKeyHex) then
        error("testCEKHex("..testCEKHex..") not equal to jweDecryptedKeyHex("..jweDecryptedKeyHex..")")
    end

    -- now use the example IV and AAD  along with the CEK to perform content encryption
    local testIV = cjson.decode("[3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104, 101]")
    local testIVByteString = cryptoLite.BAtoByteString(testIV)
    local testIVHex = cryptoLite.BAtohex(testIV)

    local testAdditionalAuthenticatedData = cjson.decode('[101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 83, 85, 48, 69, 120, 88, 122, 85, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66, 77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73, 110, 48]')
    local testAdditionalAuthenticatedDataHex = cryptoLite.BAtohex(testAdditionalAuthenticatedData)

    local addtionalAuthenticatedData = cryptoLite.utf8toBA(joseHeaderB64U)
    local addtionalAuthenticatedDataHex = cryptoLite.BAtohex(addtionalAuthenticatedData)

    -- this should not ever happen
    if not (testAdditionalAuthenticatedDataHex == addtionalAuthenticatedDataHex) then
        error("testAdditionalAuthenticatedDataHex("..testAdditionalAuthenticatedDataHex..") not equal to addtionalAuthenticatedDataHex("..addtionalAuthenticatedDataHex..")")
    end

    local addtionalAuthenticatedDataByteString = cryptoLite.BAtoByteString(addtionalAuthenticatedData)

    -- content encryption with the symmetric CEK
    local success, encryptResults = pcall(cryptoLite.encrypt, {
        plaintext = testPlainText,
        key = testCEKByteString,
        encryptionKeyAgreement = "dir",
        contentEncryptionAlgorithm = "A128CBC-HS256",
        iv = testIVByteString,
        additionalAuthenticatedData = addtionalAuthenticatedDataByteString})

    if not success then
        error("cryptoLite.encrypt failed: " .. logger.dumpAsString(encryptResults))
    end

    -- compare actual ciphertext against expected
    local testCiphertext = cjson.decode('[40, 57, 83, 181, 119, 33, 133, 148, 198, 185, 243, 24, 152, 230, 6, 75, 129, 223, 127, 19, 210, 82, 183, 230, 168, 33, 215, 104, 143, 112, 56, 102]')
    local testCiphertextHex = cryptoLite.BAtohex(testCiphertext)
    local ciphertextHex = cryptoLite.ByteStringtohex(encryptResults.ciphertext)

    if not(testCiphertextHex == ciphertextHex) then
        error("testCiphertextHex("..testCiphertextHex..") not equal to ciphertextHex("..ciphertextHex..")")
    end

    -- compare actual tag against expected
    local testTag = cjson.decode('[246, 17, 244, 190, 4, 95, 98, 3, 231, 0, 115, 157, 242, 203, 100, 191]')
    local testTagHex = cryptoLite.BAtohex(testTag)
    local tagHex = cryptoLite.ByteStringtohex(encryptResults.tag)
    if not(testTagHex == tagHex) then
        error("testTagHex("..testTagHex..") not equal to tagHex("..tagHex..")")
    end

    local jweString = joseHeaderB64U .. '.' .. cryptoLite.base64URLEncode(encryptedCEK) .. '.' .. cryptoLite.base64URLEncode(encryptResults.iv) .. '.' .. cryptoLite.base64URLEncode(encryptResults.ciphertext) .. '.' .. cryptoLite.base64URLEncode(encryptResults.tag)

    -- we cannot compare our actual jweString against test JWE because the encrypted CEK is non-deterministic but what we can do is decrypt the test JWE
    -- and make sure we get the same plaintext
    local testJWE = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0.UGhIOguC7IuEvf_NPVaXsGMoLOmwvc1GyqlIKOK1nN94nHPoltGRhWhw7Zx0-kFm1NJn8LE9XShH59_i8J0PH5ZZyNfGy2xGdULU7sHNF6Gp2vPLgNZ__deLKxGHZ7PcHALUzoOegEI-8E66jX2E4zyJKx-YxzZIItRzC5hlRirb6Y5Cl_p-ko3YvkkysZIFNPccxRU7qve1WYPxqbb2Yw8kZqa2rMWI5ng8OtvzlV7elprCbuPhcCdZ6XDP0_F8rkXds2vE4X-ncOIM8hAYHHi29NX0mcKiRaD0-D-ljQTP-cFPgwCp6X-nZZd9OHBv-B3oWh2TbqmScqXMR4gp_A.AxY8DCtDaGlsbGljb3RoZQ.KDlTtXchhZTGufMYmOYGS4HffxPSUrfmqCHXaI9wOGY.9hH0vgRfYgPnAHOd8stkvw"
    local success, decryptedTestJWEResults = pcall(
        cryptoLite.decryptJWE, 
        {
            jwe = testJWE,
            encryptionAlgorithm = "RSA1_5",
            decryptionKey = testRSAPrivateKeyPEM,
            encryptionMethod = "A128CBC-HS256"
        }
    )

    if not success then
        error("Unable to decrypt the example JWE string")
    end

    -- check that the decrypted plaintext is what we expect, as are the JWE header components for enc and alg
    local joseHeader = cjson.decode(joseHeaderStr)
    if not decryptedTestJWEResults.jweHeader.enc == joseHeader.enc then
        error("The decrypted testJWE did not have the expected encryption method")
    end
    if not decryptedTestJWEResults.jweHeader.alg == joseHeader.alg then
        error("The decrypted testJWE did not have the expected encryption algorithm")
    end

    if not (testPlainText == decryptedTestJWEResults.plaintext) then
        error("The decrypted testJWE did not match the test plaintext")
    end

    -- Wow, everthing passed!
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
local valid = (derivedKey == expectedDerivedKeyByteString)
local concatKDFText = "derivedKey: " .. cjson.encode(cryptoLite.ByteStringtoBA(derivedKey)) ..
    "\nexpectedDerivedKey: " .. cjson.encode(expectedDerivedKey) ..
    "\nEqual: " .. tostring(valid)
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

-- symmetric key encryption/decryption with A256CBC-HS512
-- 64 byte key
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
    -- salt not needed because keylength sufficient
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
        rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with A256CBC-HS512", symmetricText, success)
    else
        rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with A256CBC-HS512", "Failed during decryption: " .. logger.dumpAsString(encryptResults), success)
    end
else
    rspBody = rspBody .. createResultBlock("Symmetric key encryption/decryption with A256CBC-HS512", "Failed during encryption: " .. logger.dumpAsString(encryptResults), success)
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
rspBody = rspBody .. testJWTSignature("ES256", ecPrivateKey, ecPublicKey)

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

--
-- A test case around the data in Appendix A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1
--
local success, a1Results = pcall(jweTestCaseA1)
rspBody = rspBody .. createResultBlock("Test case around the data in Appendix A.1 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.1", (success and "Passed" or a1Results), success)

--
-- A test based around the JWE example A.2 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2
--
local success, a2Results = pcall(jweTestCaseA2)
rspBody = rspBody .. createResultBlock("Test case around the data in Appendix A.2 from https://datatracker.ietf.org/doc/html/rfc7516#appendix-A.2", (success and "Passed" or a2Results), success)

rspBody = rspBody .. "</body></html>"

HTTPResponse.setHeader("content-type", "text/html")
HTTPResponse.setBody(rspBody)
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)

