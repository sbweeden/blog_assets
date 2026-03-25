--[[
        A HTTP transformation that is used to exercise the JWK functions of the CryptoLite library

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        testjwk = testjwk.lua

        [http-transformations:testjwk]
        request-match = request:GET /testjwk *
        =============

        Then in a browser just https://yourwebseal.com/testjwk
        
        Returns JSON or HTML output based on Accept header
--]]
local logger = require 'LoggingUtils'
local cryptoLite = require "CryptoLite"
local cjson = require "cjson"

logger.debugLog("testjwk")

-- Initialize test results structure
local testResults = {
    totalTests = 0,
    successTests = 0,
    failedTests = 0,
    details = {}
}

local testId = 0

-- Helper function to add a test result
local function addTestResult(title, content, success)
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

local function compareTableFields(t1, t2, fieldsToCompare)
    for _, fieldName in ipairs(fieldsToCompare) do
        if t1[fieldName] ~= t2[fieldName] then
            return false
        end
    end
    return true
end

local function compareRSAPrivateKeys(jwk1, jwk2)
    local fieldsToCompare = {"kty", "n", "e", "d", "p", "q", "dp", "dq", "qi"}
    return compareTableFields(jwk1, jwk2, fieldsToCompare)
end

local function compareRSAPublicKeys(jwk1, jwk2)
    local fieldsToCompare = {"kty", "n", "e"}
    return compareTableFields(jwk1, jwk2, fieldsToCompare)
end

local function compareECPrivateKeys(jwk1, jwk2)
    local fieldsToCompare = {"kty", "crv", "x", "y", "d"}
    return compareTableFields(jwk1, jwk2, fieldsToCompare)
end

local function compareECPublicKeys(jwk1, jwk2)
    local fieldsToCompare = {"kty", "crv", "x", "y"}
    return compareTableFields(jwk1, jwk2, fieldsToCompare)
end

-- compare two PEM keys by checking they both start with the same BEGIN header line
-- and that the strings with all whitespace and newlines returned are the same
local function comparePEMKeys(k1, k2)
    if k1:sub(1, 26) ~= k2:sub(1, 26) then
        return false
    end
    return k1:gsub("%s+", "") == k2:gsub("%s+", "")
end


-- RSA 2048 bit key generation
--local rsaPublicKey, rsaPrivateKey = cryptoLite.generateRSAKeyPair(2048)
local rsaPublicKey = "-----BEGIN PUBLIC KEY-----\n" ..
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv9AHxwupggjn+qvCcKtp\n" ..
"YNQq8hGWJRSiBqqCqH8HlS+4GMjP9bWGe6haqhcDYwjbWPMolny1MetAPlZrnZWF\n" ..
"GnIqgDIsGjkTVd1hIapG6nTEU/YRlPjL6iO2ecM1rxw8+tOK6GguuNYWF5VAtPNo\n" ..
"jat2EJB4RarRFNnGhhlYVMaAdDjV8ehsjYbsvROMES8I9YwdKUO4cHw5xYR7PXT+\n" ..
"hnMGaid2Woz4zQuuM5RGiDhLn1oCVKLh6ogPXj8DTXeysDA/yBffLWRxm+ISWwU1\n" ..
"tTEu4ZbYYSXOje1nmVLuhKEr95kzCbaLsmPbt6H5FvJrEPDeQ3VZI17DjmVujuRX\n" ..
"awIDAQAB\n" ..
"-----END PUBLIC KEY-----\n"
-- known good
local kg_rsaPublicKeyJWK = cjson.decode([[
{
  "alg": "RS256",
  "e": "AQAB",
  "ext": true,
  "key_ops": [
    "verify"
  ],
  "kty": "RSA",
  "n": "v9AHxwupggjn-qvCcKtpYNQq8hGWJRSiBqqCqH8HlS-4GMjP9bWGe6haqhcDYwjbWPMolny1MetAPlZrnZWFGnIqgDIsGjkTVd1hIapG6nTEU_YRlPjL6iO2ecM1rxw8-tOK6GguuNYWF5VAtPNojat2EJB4RarRFNnGhhlYVMaAdDjV8ehsjYbsvROMES8I9YwdKUO4cHw5xYR7PXT-hnMGaid2Woz4zQuuM5RGiDhLn1oCVKLh6ogPXj8DTXeysDA_yBffLWRxm-ISWwU1tTEu4ZbYYSXOje1nmVLuhKEr95kzCbaLsmPbt6H5FvJrEPDeQ3VZI17DjmVujuRXaw",
  "kid": "J9YUS75+9wwVt5BVqgpnJelZCVKFcjOwIcjMAnGP6S4="
}    
]])
local kg_rsaPublicKey_PKCS1=[[
-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAv9AHxwupggjn+qvCcKtpYNQq8hGWJRSiBqqCqH8HlS+4GMjP9bWG
e6haqhcDYwjbWPMolny1MetAPlZrnZWFGnIqgDIsGjkTVd1hIapG6nTEU/YRlPjL
6iO2ecM1rxw8+tOK6GguuNYWF5VAtPNojat2EJB4RarRFNnGhhlYVMaAdDjV8ehs
jYbsvROMES8I9YwdKUO4cHw5xYR7PXT+hnMGaid2Woz4zQuuM5RGiDhLn1oCVKLh
6ogPXj8DTXeysDA/yBffLWRxm+ISWwU1tTEu4ZbYYSXOje1nmVLuhKEr95kzCbaL
smPbt6H5FvJrEPDeQ3VZI17DjmVujuRXawIDAQAB
-----END RSA PUBLIC KEY-----
]]

local rsaPrivateKey = "-----BEGIN PRIVATE KEY-----\n" ..
"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC/0AfHC6mCCOf6\n" ..
"q8Jwq2lg1CryEZYlFKIGqoKofweVL7gYyM/1tYZ7qFqqFwNjCNtY8yiWfLUx60A+\n" ..
"VmudlYUaciqAMiwaORNV3WEhqkbqdMRT9hGU+MvqI7Z5wzWvHDz604roaC641hYX\n" ..
"lUC082iNq3YQkHhFqtEU2caGGVhUxoB0ONXx6GyNhuy9E4wRLwj1jB0pQ7hwfDnF\n" ..
"hHs9dP6GcwZqJ3ZajPjNC64zlEaIOEufWgJUouHqiA9ePwNNd7KwMD/IF98tZHGb\n" ..
"4hJbBTW1MS7hlthhJc6N7WeZUu6EoSv3mTMJtouyY9u3ofkW8msQ8N5DdVkjXsOO\n" ..
"ZW6O5FdrAgMBAAECggEATkVelxusLPLjbsfeDUn1M10AtUz13uW/hEbaEFXdy0Pw\n" ..
"tLRlIBfV6+n0LUo8yJHZqD95RYdYDSm5SnbLbT+RVAxYSX2vv3eg6z3uH+WzEINb\n" ..
"hgN4gzjPRRkTojZFVtKIE7Z1DYdN4YEC/Nab0/sro/verr21RoCA1yhSuW/oOpcc\n" ..
"Bp6lJJIO42pclu/dn7rVeqJbMW+RcBurbWXOhxF4DwT7SvwYDhnYAYtOFTRYIXBA\n" ..
"sq6HcuzqY8jR/QU3cqEtGVyIGmNnm61L7Ls6nyqE+38FI8dGl001caemYYNWieHX\n" ..
"/sJz4kzLON/Ws0HAKrKcx6j8snhM5d+8xoOPvlC1cQKBgQD2CDCr1iGZKSekjt6i\n" ..
"CpKdm8KKSrEKKsP4CCggsdUFE+VVk0+xi/wWnhzbpzK6IuvEXDh0FdhJxiv6awQD\n" ..
"EfgeroIXMErlxBwawe6QV9kegFKzkccUZyqLg3LGr2gt9clX188O50t+LqD0rX1w\n" ..
"kzGcesmyB/5eUW0hrDOO+J+ckwKBgQDHlXwBOMyB6kfn1skN6GVAHcwo81t8geu5\n" ..
"OWZ2i+SZYbvp8x3ZcYzLhXJzAkrPb0eMn56NqqRxyZmRnZeQPnqhuA0pg0DGJjLf\n" ..
"KjdJvaoLpIYZ82c/lPktb9elKZPVHikNo+CrPCIdOfwX4MtZ0yaAbuhYKofmjaCz\n" ..
"C3pr8Qz4yQKBgQC+6CoEHFrjwqhtKyMbr4KG44b30e9ACWEYxBOHExZNI1wPpAfx\n" ..
"p8KLNlMEKd/VySUSr9BqW00CKdCUNpfdXgMeo6B0J9fmI97+8D6SKGhkH4SMq/BD\n" ..
"J64+pVfZTeBT0WVTUTTsxpKwrbPdSAWO5dhYKHr7NvKs8xfwSfOT293WGwKBgANx\n" ..
"vfkbbNQVIfaLS171EsI/gWV3ha2pZFMG/ZCwK1rGSALqkipNfluIywfXE0lvJzHz\n" ..
"Ez5oonvgOck8igAQQ/eEgJ2lyTliMWCOjvOz1TpsNXA/NhnvzTkOhA8yn31/DsBQ\n" ..
"grER0Zjlhkc3Nusu7Kwsvc+/tCazbQGKAivYthuZAoGBALRS7hWzwZacNwy69yA3\n" ..
"cX57zBSF+s81eqY6EoJ4FqnW/UeqmtG5TGc4sIq9WVTMNNWoJnz/sdhkqgU7D8gs\n" ..
"9HfjvozDM21I5BoHa58k5cn7qBvYrX4wHz+m0pTdvRS3I7mnbuT8zV2z4brGUqpo\n" ..
"rqDJGhbjqHtfbeGo3ttNtO/G\n" ..
"-----END PRIVATE KEY-----\n"
-- known good
local kg_rsaPrivateKeyJWK = cjson.decode([[
{
  "alg": "RS256",
  "d": "TkVelxusLPLjbsfeDUn1M10AtUz13uW_hEbaEFXdy0PwtLRlIBfV6-n0LUo8yJHZqD95RYdYDSm5SnbLbT-RVAxYSX2vv3eg6z3uH-WzEINbhgN4gzjPRRkTojZFVtKIE7Z1DYdN4YEC_Nab0_sro_verr21RoCA1yhSuW_oOpccBp6lJJIO42pclu_dn7rVeqJbMW-RcBurbWXOhxF4DwT7SvwYDhnYAYtOFTRYIXBAsq6HcuzqY8jR_QU3cqEtGVyIGmNnm61L7Ls6nyqE-38FI8dGl001caemYYNWieHX_sJz4kzLON_Ws0HAKrKcx6j8snhM5d-8xoOPvlC1cQ",
  "dp": "vugqBBxa48KobSsjG6-ChuOG99HvQAlhGMQThxMWTSNcD6QH8afCizZTBCnf1cklEq_QaltNAinQlDaX3V4DHqOgdCfX5iPe_vA-kihoZB-EjKvwQyeuPqVX2U3gU9FlU1E07MaSsK2z3UgFjuXYWCh6-zbyrPMX8Enzk9vd1hs",
  "dq": "A3G9-Rts1BUh9otLXvUSwj-BZXeFralkUwb9kLArWsZIAuqSKk1-W4jLB9cTSW8nMfMTPmiie-A5yTyKABBD94SAnaXJOWIxYI6O87PVOmw1cD82Ge_NOQ6EDzKffX8OwFCCsRHRmOWGRzc26y7srCy9z7-0JrNtAYoCK9i2G5k",
  "e": "AQAB",
  "ext": true,
  "key_ops": [
    "sign"
  ],
  "kty": "RSA",
  "n": "v9AHxwupggjn-qvCcKtpYNQq8hGWJRSiBqqCqH8HlS-4GMjP9bWGe6haqhcDYwjbWPMolny1MetAPlZrnZWFGnIqgDIsGjkTVd1hIapG6nTEU_YRlPjL6iO2ecM1rxw8-tOK6GguuNYWF5VAtPNojat2EJB4RarRFNnGhhlYVMaAdDjV8ehsjYbsvROMES8I9YwdKUO4cHw5xYR7PXT-hnMGaid2Woz4zQuuM5RGiDhLn1oCVKLh6ogPXj8DTXeysDA_yBffLWRxm-ISWwU1tTEu4ZbYYSXOje1nmVLuhKEr95kzCbaLsmPbt6H5FvJrEPDeQ3VZI17DjmVujuRXaw",
  "p": "9ggwq9YhmSknpI7eogqSnZvCikqxCirD-AgoILHVBRPlVZNPsYv8Fp4c26cyuiLrxFw4dBXYScYr-msEAxH4Hq6CFzBK5cQcGsHukFfZHoBSs5HHFGcqi4Nyxq9oLfXJV9fPDudLfi6g9K19cJMxnHrJsgf-XlFtIawzjvifnJM",
  "q": "x5V8ATjMgepH59bJDehlQB3MKPNbfIHruTlmdovkmWG76fMd2XGMy4VycwJKz29HjJ-ejaqkccmZkZ2XkD56obgNKYNAxiYy3yo3Sb2qC6SGGfNnP5T5LW_XpSmT1R4pDaPgqzwiHTn8F-DLWdMmgG7oWCqH5o2gswt6a_EM-Mk",
  "qi": "tFLuFbPBlpw3DLr3IDdxfnvMFIX6zzV6pjoSgngWqdb9R6qa0blMZziwir1ZVMw01agmfP-x2GSqBTsPyCz0d-O-jMMzbUjkGgdrnyTlyfuoG9itfjAfP6bSlN29FLcjuadu5PzNXbPhusZSqmiuoMkaFuOoe19t4aje202078Y",
  "kid": "znPDno3OfjqJAbLSD6pMkFVbMD+k3avTodfVXzDAfL8="
}
]])
local kg_rsaPrivateKey_PKCS1=[[
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAv9AHxwupggjn+qvCcKtpYNQq8hGWJRSiBqqCqH8HlS+4GMjP
9bWGe6haqhcDYwjbWPMolny1MetAPlZrnZWFGnIqgDIsGjkTVd1hIapG6nTEU/YR
lPjL6iO2ecM1rxw8+tOK6GguuNYWF5VAtPNojat2EJB4RarRFNnGhhlYVMaAdDjV
8ehsjYbsvROMES8I9YwdKUO4cHw5xYR7PXT+hnMGaid2Woz4zQuuM5RGiDhLn1oC
VKLh6ogPXj8DTXeysDA/yBffLWRxm+ISWwU1tTEu4ZbYYSXOje1nmVLuhKEr95kz
CbaLsmPbt6H5FvJrEPDeQ3VZI17DjmVujuRXawIDAQABAoIBAE5FXpcbrCzy427H
3g1J9TNdALVM9d7lv4RG2hBV3ctD8LS0ZSAX1evp9C1KPMiR2ag/eUWHWA0puUp2
y20/kVQMWEl9r793oOs97h/lsxCDW4YDeIM4z0UZE6I2RVbSiBO2dQ2HTeGBAvzW
m9P7K6P73q69tUaAgNcoUrlv6DqXHAaepSSSDuNqXJbv3Z+61XqiWzFvkXAbq21l
zocReA8E+0r8GA4Z2AGLThU0WCFwQLKuh3Ls6mPI0f0FN3KhLRlciBpjZ5utS+y7
Op8qhPt/BSPHRpdNNXGnpmGDVonh1/7Cc+JMyzjf1rNBwCqynMeo/LJ4TOXfvMaD
j75QtXECgYEA9ggwq9YhmSknpI7eogqSnZvCikqxCirD+AgoILHVBRPlVZNPsYv8
Fp4c26cyuiLrxFw4dBXYScYr+msEAxH4Hq6CFzBK5cQcGsHukFfZHoBSs5HHFGcq
i4Nyxq9oLfXJV9fPDudLfi6g9K19cJMxnHrJsgf+XlFtIawzjvifnJMCgYEAx5V8
ATjMgepH59bJDehlQB3MKPNbfIHruTlmdovkmWG76fMd2XGMy4VycwJKz29HjJ+e
jaqkccmZkZ2XkD56obgNKYNAxiYy3yo3Sb2qC6SGGfNnP5T5LW/XpSmT1R4pDaPg
qzwiHTn8F+DLWdMmgG7oWCqH5o2gswt6a/EM+MkCgYEAvugqBBxa48KobSsjG6+C
huOG99HvQAlhGMQThxMWTSNcD6QH8afCizZTBCnf1cklEq/QaltNAinQlDaX3V4D
HqOgdCfX5iPe/vA+kihoZB+EjKvwQyeuPqVX2U3gU9FlU1E07MaSsK2z3UgFjuXY
WCh6+zbyrPMX8Enzk9vd1hsCgYADcb35G2zUFSH2i0te9RLCP4Fld4WtqWRTBv2Q
sCtaxkgC6pIqTX5biMsH1xNJbycx8xM+aKJ74DnJPIoAEEP3hICdpck5YjFgjo7z
s9U6bDVwPzYZ7805DoQPMp99fw7AUIKxEdGY5YZHNzbrLuysLL3Pv7Qms20BigIr
2LYbmQKBgQC0Uu4Vs8GWnDcMuvcgN3F+e8wUhfrPNXqmOhKCeBap1v1HqprRuUxn
OLCKvVlUzDTVqCZ8/7HYZKoFOw/ILPR3476MwzNtSOQaB2ufJOXJ+6gb2K1+MB8/
ptKU3b0UtyO5p27k/M1ds+G6xlKqaK6gyRoW46h7X23hqN7bTbTvxg==
-----END RSA PRIVATE KEY-----
]]


addTestResult("RSA Keypair (2048 bits)", rsaPrivateKey .. "\n" .. rsaPublicKey, true)

-- EC key generation
-- local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair()
local ecPublicKey = "-----BEGIN PUBLIC KEY-----\n" ..
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+SP+kbAdg3AwSjqE4+jYLpY9rBSU\n" ..
"vNWnT7fwa67pr4Kw8faiBH+A0OhjNWToSISlIziXemEViqG1gtMvL1LYLg==\n" ..
"-----END PUBLIC KEY-----\n"
-- known good
local kg_ecPublicKeyJWK = cjson.decode([[
{
  "crv": "P-256",
  "ext": true,
  "key_ops": [
    "verify"
  ],
  "kty": "EC",
  "x": "-SP-kbAdg3AwSjqE4-jYLpY9rBSUvNWnT7fwa67pr4I",
  "y": "sPH2ogR_gNDoYzVk6EiEpSM4l3phFYqhtYLTLy9S2C4",
  "kid": "aNc5q5h71OJv3PFLpl1tfHGgY08ffmqzQUQJ9CEdLfM="
}
]])
local kg_ecPublicKey_PKCS1 = nil -- there is no such thing


local ecPrivateKey = "-----BEGIN PRIVATE KEY-----\n" ..
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpAeYfDXW1lyFul5w\n" ..
"wQGcteIA0jdeg6ZoINkxELMZPCahRANCAAT5I/6RsB2DcDBKOoTj6Ngulj2sFJS8\n" ..
"1adPt/BrrumvgrDx9qIEf4DQ6GM1ZOhIhKUjOJd6YRWKobWC0y8vUtgu\n" ..
"-----END PRIVATE KEY-----\n"
local kg_ecPrivateKeyJWK = cjson.decode([[
{
  "crv": "P-256",
  "d": "pAeYfDXW1lyFul5wwQGcteIA0jdeg6ZoINkxELMZPCY",
  "ext": true,
  "key_ops": [
    "sign"
  ],
  "kty": "EC",
  "x": "-SP-kbAdg3AwSjqE4-jYLpY9rBSUvNWnT7fwa67pr4I",
  "y": "sPH2ogR_gNDoYzVk6EiEpSM4l3phFYqhtYLTLy9S2C4",
  "kid": "We1SgvFtcgnU44wIt/tx6ufiMF3DjQMND/tNZzbMhPc="
}
]])
local kg_ecPrivateKey_PKCS1 = [[
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKQHmHw11tZchbpecMEBnLXiANI3XoOmaCDZMRCzGTwmoAoGCCqGSM49
AwEHoUQDQgAE+SP+kbAdg3AwSjqE4+jYLpY9rBSUvNWnT7fwa67pr4Kw8faiBH+A
0OhjNWToSISlIziXemEViqG1gtMvL1LYLg==
-----END EC PRIVATE KEY-----
]]

addTestResult("ECDSA Keypair (prime256v1)", ecPrivateKey .. "\n" .. ecPublicKey, true)

-- RSA PEM keys to JWK
local success, rsaPrivateKeyJWK = pcall(cryptoLite.PEMtoJWK, rsaPrivateKey)
if success then
    addTestResult("JWK of RSA private key PEM", "Private:\n" .. cjson.encode(rsaPrivateKeyJWK), compareRSAPrivateKeys(rsaPrivateKeyJWK, kg_rsaPrivateKeyJWK))
else
    logger.debugLog("cryptoLite.PEMtoJWK failed for rsaPrivateKeyJWK: " .. logger.dumpAsString(rsaPrivateKeyJWK))
    addTestResult("JWK of RSA private key PEM", "Failed to convert RSA private key to JWK: " .. logger.dumpAsString(rsaPrivateKeyJWK), false)
end
local success, rsaPublicKeyJWK = pcall(cryptoLite.PEMtoJWK, rsaPublicKey)
if success then
    addTestResult("JWK of RSA public key PEM", "Public:\n" .. cjson.encode(rsaPublicKeyJWK), compareRSAPublicKeys(rsaPublicKeyJWK, kg_rsaPublicKeyJWK))
else
    logger.debugLog("cryptoLite.PEMtoJWK failed for rsaPublicKeyJWK: " .. logger.dumpAsString(rsaPublicKeyJWK))
    addTestResult("JWK of RSA public key PEM", "Failed to convert RSA private key to JWK: " .. logger.dumpAsString(rsaPublicKeyJWK), false)
end

-- RSA JWK to PEM
local success, c_rsaPrivateKeyPEM = pcall(cryptoLite.jwkToPEM, kg_rsaPrivateKeyJWK)
if success then
    logger.debugLog("c_rsaPrivateKeyPEM: " .. c_rsaPrivateKeyPEM)
    logger.debugLog("rsaPrivateKey: " .. rsaPrivateKey)
    addTestResult("PEM of Known Good JWK RSA Private Key", "Private:\n" .. c_rsaPrivateKeyPEM, comparePEMKeys(c_rsaPrivateKeyPEM, kg_rsaPrivateKey_PKCS1))
else
    logger.debugLog("cryptoLite.jwkToPEM failed for kg_rsaPrivateKeyJWK: " .. logger.dumpAsString(c_rsaPrivateKeyPEM))
    addTestResult("PEM of Known Good JWK RSA Private Key", "Failed to convert JWK RSA private key to PEM: " .. logger.dumpAsString(c_rsaPublicKeyPEM), false)
end
local success, c_rsaPublicKeyPEM = pcall(cryptoLite.jwkToPEM, kg_rsaPublicKeyJWK)
if success then
    addTestResult("PEM of Known Good JWK RSA Public Key", "Public:\n" .. c_rsaPublicKeyPEM, comparePEMKeys(c_rsaPublicKeyPEM, rsaPublicKey))
else
    logger.debugLog("cryptoLite.jwkToPEM failed for kg_rsaPublicKeyJWK: " .. logger.dumpAsString(c_rsaPublicKeyPEM))
    addTestResult("PEM of Known Good JWK RSA Public Key", "Failed to convert JWK RSA public key to PEM: " .. logger.dumpAsString(c_rsaPublicKeyPEM), false)
end

-- EC PEM keys to JWK
local success, ecPrivateKeyJWK = pcall(cryptoLite.PEMtoJWK, ecPrivateKey)
if success then
    addTestResult("JWK of ec private key PEM", "Private:\n" .. cjson.encode(ecPrivateKeyJWK), compareECPrivateKeys(ecPrivateKeyJWK, kg_ecPrivateKeyJWK))
else
    logger.debugLog("cryptoLite.PEMtoJWK failed for ecPrivateKeyJWK: " .. logger.dumpAsString(ecPrivateKeyJWK))
    addTestResult("JWK of EC private key PEM", "Failed to convert EC private key to JWK: " .. logger.dumpAsString(ecPrivateKeyJWK), false)
end
local success, ecPublicKeyJWK = pcall(cryptoLite.PEMtoJWK, ecPublicKey)
if success then
    addTestResult("JWK of EC public key PEM", "Public:\n" .. cjson.encode(ecPublicKeyJWK), compareECPublicKeys(ecPublicKeyJWK, kg_ecPublicKeyJWK))
else
    logger.debugLog("cryptoLite.PEMtoJWK failed for ecPublicKeyJWK: " .. logger.dumpAsString(ecPublicKeyJWK))
    addTestResult("JWK of EC public key PEM", "Failed to convert EC private key to JWK: " .. logger.dumpAsString(ecPublicKeyJWK), false)
end

-- EC JWK to PEM
local success, c_ecPrivateKeyPEM = pcall(cryptoLite.jwkToPEM, kg_ecPrivateKeyJWK)
if success then
    addTestResult("PEM of Known Good JWK EC Private Key", "Private:\n" .. c_ecPrivateKeyPEM, comparePEMKeys(c_ecPrivateKeyPEM, kg_ecPrivateKey_PKCS1))
else
    logger.debugLog("cryptoLite.jwkToPEM failed for kg_ecPrivateKeyJWK: " .. logger.dumpAsString(c_ecPrivateKeyPEM))
    addTestResult("PEM of Known Good JWK EC Private Key", "Failed to convert JWK EC private key to PEM: " .. logger.dumpAsString(c_ecPublicKeyPEM), false)
end
local success, c_ecPublicKeyPEM = pcall(cryptoLite.jwkToPEM, kg_ecPublicKeyJWK)
if success then
    addTestResult("PEM of Known Good JWK EC Public Key", "Public:\n" .. c_ecPublicKeyPEM, comparePEMKeys(c_ecPublicKeyPEM, ecPublicKey))
else
    logger.debugLog("cryptoLite.jwkToPEM failed for kg_ecPublicKeyJWK: " .. logger.dumpAsString(c_ecPublicKeyPEM))
    addTestResult("PEM of Known Good JWK EC Public Key", "Failed to convert JWK EC public key to PEM: " .. logger.dumpAsString(c_ecPublicKeyPEM), false)
end

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
    htmlBody = htmlBody .. '<h2>JWK Test Results Summary</h2>'
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

