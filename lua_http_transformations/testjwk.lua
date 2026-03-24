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
--]]
local logger = require 'LoggingUtils'
local cryptoLite = require "CryptoLite"
local cjson = require "cjson"

function preBlockWithTitle(title, text)
    return "<div style='border: 1px solid black; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end

function errorBlockWithTitle(title, text)
    return "<div style='border: 1px solid red; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end


logger.debugLog("testjwtutils")

local rspBody = "<html><body>"

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


rspBody = rspBody .. preBlockWithTitle("RSA Keypair (2048 bits)", rsaPrivateKey .. "\n" .. rsaPublicKey)

-- EC key generation
-- local ecPublicKey, ecPrivateKey = cryptoLite.generateECDSAKeyPair()
local ecPublicKey = "-----BEGIN PUBLIC KEY-----\n" ..
"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+SP+kbAdg3AwSjqE4+jYLpY9rBSU\n" ..
"vNWnT7fwa67pr4Kw8faiBH+A0OhjNWToSISlIziXemEViqG1gtMvL1LYLg==\n" ..
"-----END PUBLIC KEY-----\n"

local ecPrivateKey = "-----BEGIN PRIVATE KEY-----\n" ..
"MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgpAeYfDXW1lyFul5w\n" ..
"wQGcteIA0jdeg6ZoINkxELMZPCahRANCAAT5I/6RsB2DcDBKOoTj6Ngulj2sFJS8\n" ..
"1adPt/BrrumvgrDx9qIEf4DQ6GM1ZOhIhKUjOJd6YRWKobWC0y8vUtgu\n" ..
"-----END PRIVATE KEY-----\n"


rspBody = rspBody .. preBlockWithTitle("ECDSA Keypair (prime256v1)", ecPrivateKey .. "\n" .. ecPublicKey)

-- RSA PEM keys to JWK
local success, rsaPrivateKeyJWK = pcall(cryptoLite.PEMtoJWK, rsaPrivateKey)
if not success then
    logger.debugLog("cryptoLite.PEMtoJWK failed for rsaPrivateKeyJWK: " .. logger.dumpAsString(rsaPublicKeyJWK))
end
local success, rsaPublicKeyJWK = pcall(cryptoLite.PEMtoJWK, rsaPublicKey)
if not success then
    logger.debugLog("cryptoLite.PEMtoJWK failed for rsaPublicKeyJWK: " .. logger.dumpAsString(rsaPublicKeyJWK))
end
logger.debugLog("rsaPrivateKeyJWK: " .. logger.dumpAsString(rsaPrivateKeyJWK) .. " rsaPublicKeyJWK: " .. logger.dumpAsString(rsaPublicKeyJWK))

rspBody = rspBody .. preBlockWithTitle("JWK of RSA keys", "Private:\n" .. cjson.encode(rsaPrivateKeyJWK) .. "\nPublic:\n" .. cjson.encode(rsaPublicKeyJWK))

-- EC PEM keys to JWK
local success, ecPrivateKeyJWK = pcall(cryptoLite.PEMtoJWK, ecPrivateKey)
if not success then
    logger.debugLog("cryptoLite.PEMtoJWK failed for ecPrivateKeyJWK: " .. logger.dumpAsString(ecPrivateKeyJWK))
end
local success, ecPublicKeyJWK = pcall(cryptoLite.PEMtoJWK, ecPublicKey)
if not success then
    logger.debugLog("cryptoLite.PEMtoJWK failed for ecPublicKeyJWK: " .. logger.dumpAsString(ecPublicKeyJWK))
end

logger.debugLog("ecPrivateKeyJWK: " .. logger.dumpAsString(ecPrivateKeyJWK) .. " ecPublicKeyJWK: " .. logger.dumpAsString(ecPublicKeyJWK))
        
rspBody = rspBody .. preBlockWithTitle("JWK of EC keys", "Private:\n" .. cjson.encode(ecPrivateKeyJWK) .. "\nPublic:\n" .. cjson.encode(ecPublicKeyJWK))


rspBody = rspBody .. "</body></html>"

HTTPResponse.setHeader("content-type", "text/html")
HTTPResponse.setBody(rspBody)
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)

