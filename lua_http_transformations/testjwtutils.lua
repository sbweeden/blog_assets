--[[
        A HTTP transformation that is used to exercise the JWTUtils functions

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        testjwtutils = testjwtutils.lua

        [http-transformations:testjwtutils]
        request-match = request:GET /testjwtutils *
        =============

        Then in a browser just https://yourwebseal.com/testjwtutils
--]]
local logger = require 'LoggingUtils'
local cryptoLite = require "CryptoLite"
local jwtUtils = require 'JWTUtils2'
local cjson = require "cjson"

logger.debugLog("testjwtutils")

local rspBody = "<html><body>"

local function preBlockWithTitle(title, text)
    return "<div style='border: 1px solid black; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end

local function errorBlockWithTitle(title, text)
    return "<div style='border: 1px solid red; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end

local function testJWTGenerateValidate(title, jwtGenerateOptions, jwtValidateOptions)

    local txt = ""
    local generatedJWT = nil
    -- attempt generation if requested
    if (jwtGenerateOptions ~= nil) then
        local success, jwt = pcall(jwtUtils.generate, jwtGenerateOptions)

        if (success) then
            txt = "JWT: " .. jwt
            generatedJWT = jwt
        else
            rspBody = rspBody .. errorBlockWithTitle(title, "Failed to generate with error: " .. jwt)
            return nil
        end
    end

    -- attempt validation if requested
    if (jwtValidateOptions ~= nil) then
        -- update the validation options with the jwt we just generated if we did generation
        if (generatedJWT ~= nil) then
            jwtValidateOptions.jwt = generatedJWT
        end

        -- attempt validation
        local success, validationResults = pcall(jwtUtils.validate, jwtValidateOptions)
        if success then
            local header = validationResults.jwtHeader
            local claims = validationResults.jwtClaims
            txt = txt .. (#txt > 0 and "" or ("JWT: " .. jwtValidateOptions.jwt)) .. "\nValid: " .. tostring(success) .. "\nHeader: " .. cjson.encode(header) .. "\nClaims: " .. cjson.encode(claims)
        else
            rspBody = rspBody .. errorBlockWithTitle(title, txt .. "\nValidation failed: " .. tostring(success) .. "\nError: " .. validationResults)
            return nil
        end
    end
    rspBody = rspBody .. preBlockWithTitle(title, txt)
end

local function testJWTEncryptDecrypt(title, jweGenerateOptions, jweValidateOptions)

    local txt = ""
    local generatedJWE = nil
    -- attempt generation if requested
    if (jweGenerateOptions ~= nil) then
        local success, jwe = pcall(jwtUtils.generateEncrypted, jweGenerateOptions)
        if success then
            txt = "JWE: " .. jwe
            generatedJWE = jwe
        else
            rspBody = rspBody .. errorBlockWithTitle(title, "Failed to generate encrypted with error: " .. logger.dumpAsString(jwe))
            return nil
        end
    end

    -- attempt validation if requested
    if (jweValidateOptions ~= nil) then
        -- update the validation options with the jwe we just generated if we did generation
        if (generatedJWE ~= nil) then
            jweValidateOptions.jwe = generatedJWE
        end

        -- attempt validation
        local success, validationResults = pcall(jwtUtils.validateEncrypted, jweValidateOptions)
        if success then
            local jweHeader = validationResults.jweHeader
            local header = validationResults.jwtHeader
            local claims = validationResults.jwtClaims
            txt = txt .. (#txt > 0 and "" or ("JWE: " .. jweValidateOptions.jwe)) .. "\nValid: " .. tostring(success) .. "\nJWE Header: " .. cjson.encode(jweHeader) .. "\nHeader: " .. cjson.encode(header) .. "\nClaims: " .. cjson.encode(claims)
        else
            rspBody = rspBody .. errorBlockWithTitle(title, txt .. "\nValidation failed: " .. tostring(success) .. "\nError: " .. validationResults)
            return nil
        end
    end
    rspBody = rspBody .. preBlockWithTitle(title, txt)
end


-- RSA 2048 bit key generation
local rsaPublicKey, rsaPrivateKey = cryptoLite.generateRSAKeyPair(2048)
rspBody = rspBody .. preBlockWithTitle("RSA Keypair (2048 bits)", rsaPrivateKey .. "\n" .. rsaPublicKey)

-- EC key generation
local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair("prime256v1")
rspBody = rspBody .. preBlockWithTitle("ECDSA Keypair (prime256v1)", ecPrivateKey .. "\n" .. ecPublicKey)

-- basic JWT with no signature
logger.debugLog("Generate/Validate JWT with none")
local jwtClaims = { sub = "testuser" }
local jwtGenerateOptions = {
    header = {alg = "none", typ = "JWT"},
    claims = jwtClaims,
    algorithm = "none"
}
local jwtValidateOptions = {
    algorithm = "none",
    validateExp = false
}
testJWTGenerateValidate("Generate/Validate JWT with none algorithm", jwtGenerateOptions, jwtValidateOptions)

-- JWT with HS256
logger.debugLog("Generate/Validate JWT with HS256")
local secretKey = "not_really_a_secret"
jwtGenerateOptions = {
    header = {alg = "HS256", typ = "JWT"},
    claims = jwtClaims,
    algorithm = "HS256",
    key = secretKey
}
jwtValidateOptions = {
    algorithm = "HS256",
    key = secretKey,
    validateExp = false
}
testJWTGenerateValidate("Generate/Validate JWT with HS256", jwtGenerateOptions, jwtValidateOptions)

-- JWT with RS256
logger.debugLog("Generate/Validate JWT with RS256")
jwtGenerateOptions = {
    header = {alg = "RS256", typ = "JWT"},
    claims = jwtClaims,
    algorithm = "RS256",
    key = rsaPrivateKey
}
jwtValidateOptions = {
    algorithm = "RS256",
    key = rsaPublicKey,
    validateExp = false
}
testJWTGenerateValidate("Generate/Validate JWT with RS256", jwtGenerateOptions, jwtValidateOptions)

-- JWT with ES256
logger.debugLog("Generate/Validate JWT with ES256")
jwtGenerateOptions = {
    header = {alg = "ES256", typ = "JWT"},
    claims = jwtClaims,
    algorithm = "ES256",
    key = ecPrivateKey
}
jwtValidateOptions = {
        algorithm = "ES256",
        key = ecPublicKey,
        validateExp = false
    }
testJWTGenerateValidate("Generate/Validate JWT with ES256", jwtGenerateOptions, jwtValidateOptions)

-- Encrypted JWT with RSA
logger.debugLog("Encrypt/Descrypt JWT with RS256")
local jweGenerateOptions = {
    claims = jwtClaims,
    signatureAlgorithm = "RS256",
    signatureKey = rsaPrivateKey,
    encryptionAlgorithm = "RSA-OAEP",
    encryptionKey = rsaPublicKey,
    encryptionMethod = "A256GCM",
    kid = "testkid"
}
local jweValidateOptions = {
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = rsaPrivateKey,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    signatureKey = rsaPublicKey,
    validateExp = false
}
testJWTEncryptDecrypt("Encrypt/Decrypt JWT with RS256, RSA-OAEP, A256GCM", jweGenerateOptions, jweValidateOptions)

-- Decrypted JWT with RSA (External example)
local testExternalPrivateKeyPEM = [[
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC19iSgRR1pujPw
w0ToB/nHu3Su1zqVEt4gI2zE/kSEk4Yw3FDgeao5pK+PXpaOQUpplqNhy804ZhrT
X6+0ify+0I5I23isjkUUwFf7GIBMCBhHzfclHr1r0ChBAREA1QA1UiGgmvAUZUYv
NxTMARp8NJWnNA6kr7cuH7ziCsOPhTEmS1iTPUJ7RA2lEmm/1Sv5uRUGPtgOC8bt
r1w0GV22ax8tsfThW8La+pWHEtjF+N7Rp4aQ89yamvztUFt0XMjsJChOAMD/HVnw
P1S0p5qQ6eTeSBYkYScZYc1UMqhbE/Phjt846Cy+GDBB/KEM45Vl5L9VkLZ7NYA7
T0LaCeU3AgMBAAECggEABSAsA7rc58z6bAdAkxoFhnVfsC58lIccwZs6TND1PyZd
lzk0quqNHx3mKQS6+vuKTBNcybwfZiFs2gZVAUyYce8lX12Vi90KGOhTfM2XGymh
bz4nDOExIXYEMZpaa7U+/Jbc6aLwH0EuLpy/mVY39Dhnblsctu47xmnXkibyW/rn
h5DWTTo+Ra4K7aNPCmnn1U85E9/IQZzk8hmfF3F/3dSl3YU4Igj+UqLMtCM7IE0M
q0RtiTeKJIYOB1BNm4GmatJtUVq+NVc67ISVioSGtJht9ubElqV4Yxw6FvOa1lyU
j5wY17Yn+N+vhZKIsQBt7i4fAE9RpjO18fv3Z0GV2QKBgQDsTFJbZwhFgDfwz98k
CNAEserFM1j6Ml4ILXXg9AhNARXzildkZ8rXwSVbtRjZMLSXdMZeu/RR+YCQx7qG
+GhqqFdUbRwtRmfVH7IkoKeCbe+IgF+df3cJh/TOYjIY4PtVL653goAqQPfj6JJf
ku0IVGzd4/XQYQ7kpAhqqgduRQKBgQDFIge00wNOUEE7NwmbqsdFvh1E5tL9S/r7
291NEG+z+C1iMGZuIGJCn0cqWBhE1C7dur7eqeB13cRa6oMa6J7hkOQujXty6CKN
vWgALTqc43LNfa9o9pksgphrBX05Hv5oGBu5UrvPaGtbMoiWf80hBYE1P5vUN/Ib
x5Ow3esrSwKBgG++Z/PxdWfoiovGwa84u6Z8vJkk/x7SUsVrOiN3Q7Wmncrd0RYa
P0JohFIqAeYzsjMtdeG24IMjijjtOrg5IKfPk/zI3FpMwS14H7ZSguSbOHtEufKx
JInNUWeH6Ej7m99c/RRnElTpBFEy2oV35b/arOEBvG0eePyG1bQbVAhBAoGAXmSW
FhK4UYaCRa1r71sOAiovb6+rNdhs/K5hwCXvptheOtb8JR1ij44fEHqQXFzReCCU
hqAHN8kR3YrPblIWyeGMMXJTu0jGSuJ36yW9HCSY8yaMmJED9VkvTIebV3+syAFL
PSkNfxn71fZTiuT1PyuYm/uyTSLgzkZ5RMZudhMCgYBy8BbGhHkYaxLByrrh5FGv
X+yQy+yqE495IRrQDGhoUbNoNir0xfoz1k/+u27+tF9IipOgFORh6zeARMQk/TSw
251GGUUqIr90YjB42a5E5d9CLGFsrtRFGtLL7NkNARP87l17/QnjKXyuaF9BXEsV
KJCSwb1Q2HeLJJbBJwo5DQ==
-----END PRIVATE KEY-----
]]
local testExternalPubliKeyPEM = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtfYkoEUdaboz8MNE6Af5
x7t0rtc6lRLeICNsxP5EhJOGMNxQ4HmqOaSvj16WjkFKaZajYcvNOGYa01+vtIn8
vtCOSNt4rI5FFMBX+xiATAgYR833JR69a9AoQQERANUANVIhoJrwFGVGLzcUzAEa
fDSVpzQOpK+3Lh+84grDj4UxJktYkz1Ce0QNpRJpv9Ur+bkVBj7YDgvG7a9cNBld
tmsfLbH04VvC2vqVhxLYxfje0aeGkPPcmpr87VBbdFzI7CQoTgDA/x1Z8D9UtKea
kOnk3kgWJGEnGWHNVDKoWxPz4Y7fOOgsvhgwQfyhDOOVZeS/VZC2ezWAO09C2gnl
NwIDAQAB
-----END PUBLIC KEY-----
]]

logger.debugLog("Decrypt JWT with RS256, RSA-OAEP, A256GCM - JWE external example generated at: https://www.authgear.com/tools/jwt-jwe-debugger")
local jweValidateOptions = {
    jwe = "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkEyNTZHQ00ifQ.DQ3v_G3ww1aDd9n2rxeAI1K2Q2KSgYYY9lSFQK1tQHavWPjl9eyV5NrQcTVa7s9apyFhO07nbgeQ8X7rlej5OK0k3nbZvZ_wrlfTj9u8pOLNMUcHU0GeYDAKnWpg-r_o1eZ3pMI6GDyA_Hk4Pe4qVUqrGnCiaSDLoadn1z1XuU3_9D6EvSO2dlfJfqN0bDAAwsZCf_jL2H2gE4GHUjwj4xf24J01oBvWl0GIth4xpuRmBRMC8QW4OtgfBQOzOFq6HySCI9WcNLppL1lkzYwSGE4_yv4OPmWEss3JOEwH2stxxObiFjDroSG9XFWaiX07wubi-MmUWEqpSxUSY2Nw7g.3d4B8IP6GsIgilAr.n0XKmgA27Z-hvrrIMqLo-w7yDBp91leTNUhwp2B-g3nZj6C-YEi50Rqin7yh2NyNJqc9_vXFWlYgyHhketYPDeEQefj5ACYkFzEqvs42U1Z94E9PD53yWGLodp3H_HbtbY2iX0IA6iFCn5vRR01Yt7kaMOKLdOKoe1FzAhDOs2O0d0QIA4zoojxEsCVYoddgGERRmsjbhyDpDRbOHcl_azsD3CWmf97JJ31EZdSwThjdw1UT0q7M7-iii41dCUG5sRFOEY6b0_dWFqJ1grIbC0iCAqnqd2UO9f6eGRbK4KOCZAF1-qJt9j2IpzkhPvHdLmfMYBDnWI1WTZOz2g6EqgoXwOSdwWZ4RBXuGQx4NPZPJKu-ToP1BFGmHfxkpmOoJQSuc2nI7E9-KQ9I99JwJ0Wx7ds2XP3DVCECptl63r3ehPLkurR07H0KmiUgbaWDeqelVdr5P793mP4pM6ICj0UmjX8860jVXxKjrigZL30s_pSjeWZINKDi7msyadD7Q-YlRTmSArTwA9cM4GfeJL5xnFk4ugVf7n0k5WJR0kJc5gh_ygmyjaYS8ihu_Jq6kdQSv6I9otOZYRXPTGc618CsVwQxEBkxUl_9JTuYNJmams6mmcA76siV5A.erCmXNrk8hbhevveF9o-bg",
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = testExternalPrivateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    signatureKey = testExternalPubliKeyPEM,
    validateExp = false
}
testJWTEncryptDecrypt("Decrypt JWT with RS256, RSA-OAEP, A256GCM - JWE external example generated at: https://www.authgear.com/tools/jwt-jwe-debugger", nil, jweValidateOptions)


-- Decrypt with RSA (WebSEAL remember-session token example)
logger.debugLog("Decrypt JWT with RS256, RSA-OAEP, A256GCM - WebSEAL remember-session example")
local webSEALPrivateKeyPEM = [[
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDVyDMYON39+2gR
P4xsc21QX2O33RyCUseiE7bo499j44Tbzaf7S0ocxJKGieLUqJUXPT09H5nwH+69
ziEcBl3/6P3odbiYYafdAl+K2b43jpmiW6/IrA0ZcEVmw8gQp2Gpm7yxI3P/L/Fu
gwkIGonITmNzfJGDsXPwMYKnF1+FZoTTc/V8V4JcnV893Hkd2kQ2ezd0gDxMW/Xf
3pRuBr5ZI+SIFzhKoKjlF8Mtx7dTYFfB2Yo0hGxI67A1Buk3cnyiHa9Tyb2G9ey8
aQ5FlQVKd1KhBiy3qYdYRoc8+AuD76yyKnbfEujHvFMqkbHPnIZQrUPAHzpNHodm
E8Q5UrXFAgMBAAECggEAPb0D2H5vyc4Fl1mZZaaODrSFmU8/UPm0EoAMBkTsui22
LD4/wWhUXmt8f2MpwU1wRRZX7aOHMtwd9+2kDTJfiizQywXYShWFw2NQkUphzyyc
/NDqupLJc6vDNzLaP8j/ANrriuKYuL0xRb+M56y2VsUgnnT+lyAzwc2ilDvBR8Y0
83ROhjOyddeOLUtG5uUSfxPxbRmqwX8nBRMnFxXEN7W9H9Z3Xi248uT03AWf3986
NvS9ed6lmkF3rJY0SrL6E111+eujg77Qe32JPcJfeRUZaKkS4irHAmxToG2u9HEm
viTFJi8/1m2J+h2cAKf0lWSUr9JtpHGTQXmZ2+OlfwKBgQDvre0q5SNBb0ivQCJN
Bu1kUxU9bjv93cpAjgoAdQNsSEO/K+0J6cerEtBNtnM3V+YvdLmkO/dtG4A9Sje4
bbT2pfG4aR1vDswXhgQ7XicIoSyfglTDzQoh6AIWithFIGWcFX3gA43tRLyN5LEm
kSeuJJ50zZyhoQtTD9N1BQ0/lwKBgQDkVtUE8tASL/rhm0df1Lq2/0NDGSCZGDM4
3SAqd3S+3pRnDEyaIZzAbpm6NKIwHjlfmZFEecNYO+X7YWFF6r813anQCaxSKCOb
meCcWYGmj+VPEILffS5400sgzsgS6tM0S+BbKvdBs9mWhKnnbUi2a4UICP7d97dd
7cBO6duhAwKBgFAOJgOH2YjHpN10bICR6cTyw0trgHpBFIcPamPQsb3/PTGjeF8x
SNHpTM5IPJ+lqmr7b+5dYT1+TA0stwPREPq5Xs2bvosTxDOvPcaeoicNvpvgqnNk
DxhYKCpjYe1k7st9mjeyuDsiFGDInCsnnLtb29ljvAd4hRHPXW/eqhgtAoGBALw5
E7nTik8ju/QTMv+89Pj6bHC4GtX4S+j45pX7CIJ6KezUB6UaRgOeaBxFXNi7YWH7
zfKbSLrIDWltuWiP/HSjt2JlRuYmbkvKyYs4gRZTEZxeKPOfVhqFWi2+JtDpP5ah
YVzlixJe9eMMkp3RyRmOggfAmo9Qrpe/70Fdpw0PAoGBAKiYv73s7LiQ6rLeq8CH
mID7Eu6UC3FEyaA+LMSsiitXSwK7Yfm+fLAFrmFsP2tiUVU1CoHoTYAACd1H1+28
jWCEpOwDUk3mXKPDDjyQ47F8kpvWJpurDBWMHBpKKKnrHQyQcfbI4QHBs2WjhddP
nsBYUPVNYYqUae+tqDyBHDtP
-----END PRIVATE KEY-----
]]
local webSEALPublicKeyPEM = [[
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1cgzGDjd/ftoET+MbHNt
UF9jt90cglLHohO26OPfY+OE282n+0tKHMSShoni1KiVFz09PR+Z8B/uvc4hHAZd
/+j96HW4mGGn3QJfitm+N46ZoluvyKwNGXBFZsPIEKdhqZu8sSNz/y/xboMJCBqJ
yE5jc3yRg7Fz8DGCpxdfhWaE03P1fFeCXJ1fPdx5HdpENns3dIA8TFv1396Ubga+
WSPkiBc4SqCo5RfDLce3U2BXwdmKNIRsSOuwNQbpN3J8oh2vU8m9hvXsvGkORZUF
SndSoQYst6mHWEaHPPgLg++ssip23xLox7xTKpGxz5yGUK1DwB86TR6HZhPEOVK1
xQIDAQAB
-----END PUBLIC KEY-----
]]
local webSEALJWE = "eyJlbmMiOiAiQTI1NkdDTSIsICJhbGciOiAiUlNBLU9BRVAiLCAia2lkIjogIldlYlNFQUwtVGVzdC1Pbmx5IiwgImN0eSI6ICJKV1QiLCAiemlwIjogIkRFRiJ9.hOKSj_v9KiwKfpn5xhYOM7iyis7GJ5i5ZbMCGDUmuwTHCfQ9Cp6CeUvOZBAKoX3__P1ApaziC1h6_gjwonHDV-oz_Pn13O8w6zKY33x14Jl7Nbwbl9sbmRsCwP1SE4YkLok27YywSGNb_FZ3DRgPt_4C-JwXW1q85juBu74NoVC2OjfJ9pP13J2qAR9EBuaqHnF5Z1N3TuEoGPbGCngk7hP5nXosocH69stMTlvoTfB5bfzROI5-8DiBbMjVnN19rxrk4ikESGLNKpmWdZrmgKfbZtzgz9mHAoN3lcTda2xcyfWQnyn2UFoCRoHLhunfRYtiCg562cXe3UuwgPGACQ.6HWxHR8_mnhVQwny.sa_08TL97jVMU8oEzTHozG_RcgxuqBn9OLb6s9dEGU0RLP_tfJrGKEXWfBVahX6e0FZZOEWTaPvQXWKi9D-mw0fY_-an8e75p7uA7uYb1vxM0273AHAkB9UgLVp-63oF-lEqSy7OCvedEYRspwZSGpfJdlkRf0rwuLlrmMAxhl52BhQizbRT646GVYMs4TbJc8S6wB8C39scR2R1Gk_dDlBlRKEWco4j8gUvkqV2EYqsnVZotaFh-MZm_rzQAjWLcMUP8a_S8jD0yM9adt-XXSQ28kojP7kTNFgPu8JVDZ-BBVjNErIqNS10To8-pjnkA6T9r_Sn4H6vf__6u2sp-p514_vKBNnhz5zIelEwWPJ7dO4UOHQA347GOUWoN5W5plpSt8w07e07iUCTv55fZgyqpVmRKCehHUx3ArJqDk8qtpAHvjs0BYluQM0--Od0_GgjRpkyd63rzeCWH3B3nf3T-6kThWwgUQcURPhJvVGPqPUbq2plQ7UE8-_uI2j2RAmdXD5XxSC2sUrNiM2i-WohTz-Z60lb0P8p2yj0M3JFOz9VpUagMHGZFvinVdKf0OecORRyRc_6QZumTbm8Lx6SI1wsNLV3lf0DzoDjOQMptq-0R0gPTTg5FNvE-vmRhnKiwz2pMu6HxW_cw-4nrrfjOmFxSZbzOZZ94puZ7I5YtaB59yaCG3-aaeGnlwsVChXrpv_nbXtPEqvPzDBcP3zu9waKaI3uat2p6ZISU4787lufWwSy8CwEEcBPXMrDcP58VFeOQQDwtRRa.D-hMpUN1r61XCFRH-R0Ojw"
local jweValidateOptions = {
    jwe = webSEALJWE,
    encryptionAlgorithm = "RSA-OAEP",
    decryptionKey = webSEALPrivateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "RS256",
    signatureKey = webSEALPublicKeyPEM,
    validateExp = false
}
testJWTEncryptDecrypt("Decrypt JWT with RS256, RSA-OAEP, A256GCM - WebSEAL remember-session example", nil, jweValidateOptions)


-- Encrypted JWT with ES256, ECDH-ES and A256GCM
logger.debugLog("Encrypted JWT with ECDH-ES")
local jweGenerateOptions = {
    claims = jwtClaims,
    signatureAlgorithm = "ES256",
    signatureKey = ecPrivateKey,
    encryptionAlgorithm = "ECDH-ES",
    encryptionKey = ecPublicKey,
    encryptionMethod = "A256GCM",
    kid = "testkid"
}
local jweValidateOptions = {
    encryptionAlgorithm = "ECDH-ES",
    decryptionKey = ecPrivateKey,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "ES256",
    signatureKey = ecPublicKey,
    validateExp = false
}
testJWTEncryptDecrypt("Encrypt/Decrypt JWT with ES256, ECDH-ES, A256GCM", jweGenerateOptions, jweValidateOptions)

--
-- Decrypt a JWT generated by the TFIM STS using ECDHS-ES
--

logger.debugLog("Decrypt JWT with ES256, ECDH-ES, A256GCM - JWT from IVIA STS")
local websealEC256_privateKeyPEM = [[
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/lllBMCTzRWOVoxn
q5I5zFieh8esRSsCPBYNcx1ce9ihRANCAAQgaWojlBcZ9mzm2Fxv9SvCUPoV6RP/
04Ihf5CzTTWJUmf8yBaG5uVK5+Uw+WnjoMwojUL4NAoRAwN/Z9dg/lmT
-----END PRIVATE KEY-----
]]
local websealEC256_publicKeyPEM = [[
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIGlqI5QXGfZs5thcb/UrwlD6FekT
/9OCIX+Qs001iVJn/MgWhublSuflMPlp46DMKI1C+DQKEQMDf2fXYP5Zkw==
-----END PUBLIC KEY-----
]]
local jweECDHES_fromTFIMSTS = "eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImtpZCI6IndYcjI4aUFuQ2VfVURJdl9vQll0aUpkTjdTU3I0MkJjMWdYV01XQkNCWlEiLCJjdHkiOiJKV1QiLCJlcGsiOnsia3R5IjoiRUMiLCJ4IjoiSlpjaVNkZkM1S3puUm00SnNQajZFTjVUenNNUzZ1NU1Cbi0tNHFBMWducyIsInkiOiJfMHBwWGlwWHpPckVNUExTQ0VwbDZUR0ZZbS1QbmVfbk52QXVqSFdrZ1djIiwiY3J2IjoiUC0yNTYifX0..T-c61_Q-4TSOeORL.jbJ4xUAjaui6Isp9YshJqi0rsUsEnuTuIM8idOfNIHAMQ4nkiSvqhsMbaqsPnTi75fJaK7KDbMMGGUq1VK_tvgmoAGLMAybmIq_tj53y0TOjQYSFUPsBvmewWDnBVgeIjl69GYX-7YKondEK1C8ZQxdi43yFJs9BYTxyiZ24qZSq2kyZMK-ZEqknOy2b4pzXQHwXeNmGMzr3sy_ahOv-BZqDUM6hAA0de85dMXr8MTbtOIzMjIH-gYseHxR0aTTtIYdi3-0no8Lfvu9Ypcz3H8lTnGi1c7xhZp9rDO7Be49UdNb7nbNBYy-K.y-f0ODYVjCpy7zUWRTxHFQ"

local jweValidateOptions = {
    jwe = jweECDHES_fromTFIMSTS,
    encryptionAlgorithm = "ECDH-ES",
    decryptionKey = websealEC256_privateKeyPEM,
    encryptionMethod = "A256GCM",
    signatureAlgorithm = "ES256",
    signatureKey = websealEC256_publicKeyPEM,
    validateExp = false
}
testJWTEncryptDecrypt("Decrypt JWT with ES256, ECDH-ES, A256GCM - JWT from IVIA STS", nil, jweValidateOptions)

rspBody = rspBody .. "</body></html>"

HTTPResponse.setHeader("content-type", "text/html")
HTTPResponse.setBody(rspBody)
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)
