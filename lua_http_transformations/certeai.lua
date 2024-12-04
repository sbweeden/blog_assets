--[[
        A transformation that unpacks an X509 certificate for the purposes of it being used as a certificate EAI

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        certeai = certeai.lua

        [http-transformations:certeai]
        request-match = request:POST /certeai *
        =============
		
		You would also need to set up certificate EAI to point at /certeai.
		
		For information on the openssl.x509 APIs, consult the luaossl PDF found here: 
			https://www.25thandclement.com/~william/projects/luaossl.pdf
			
		This is referenced from: https://luarocks.org/modules/daurnimator/luaossl
		
--]]

local cjson = require "cjson"
local logger = require "LoggingUtils"
local x509 = require "openssl.x509"
local ber = require "ber"

-- This table maps common DN OIDs to the tag used in a printable DN
local dnOIDTable = {
    ["0.9.2342.19200300.100.1.1"] = "UID",
    ["0.9.2342.19200300.100.1.3"] = "mail",
    ["0.9.2342.19200300.100.1.25"] = "DC",
    ["2.5.4.3"] = "CN",
    ["2.5.4.4"] = "SN",
    ["2.5.4.5"] = "serialNumber",
    ["2.5.4.6"] = "C",
    ["2.5.4.7"] = "L",
    ["2.5.4.8"] = "ST",
    ["2.5.4.9"] = "street",
    ["2.5.4.10"] = "O",
    ["2.5.4.11"] = "OU",
    ["2.5.4.12"] = "title",
    ["2.5.4.13"] = "description"
}

-- This table maps data types to a string used in the DN parsing output (see decodeDirName)
local dsTable = {
    [12] = "utf8",
    [19] = "prn",
    [22] = "ia5"
}

-- In case we decide to do any up-front validation of parameters, this is useful for sending back an error
function errorResponse(str)
    local errJSON = {}
    errJSON["error"] = str
    HTTPResponse.setHeader("content-type", "application/json")
    HTTPResponse.setStatusCode(400)
    HTTPResponse.setStatusMsg("Bad Request")
    HTTPResponse.setBody(cjson.encode(errJSON))

    Control.responseGenerated(true)
end

-- decodes a DirectoryString (see DirectoryString definition in https://datatracker.ietf.org/doc/html/rfc5280)
-- PrintableString=19, TeletexString=20 (aka T61String), UniversalString=28, UTF8String=12, BMPString=30
function decodeDirectoryString(data)
    local result = nil
    local decodeResult = ber.decode(data)
    if (decodeResult ~= nil and decodeResult["class"] == 0 and decodeResult["data"] ~= nil and (decodeResult["type"] == 19 or decodeResult["type"] == 20 or decodeResult["type"] == 28 or decodeResult["type"] == 12 or decodeResult["type"] == 30)) then
        result = decodeResult["data"]
    else
        result = nil
        logger.debugLog("decodeDirectoryString invalid ber data")
    end
    return result
end

-- decodes an OID into a printable string
function decodeOID(data, len)
    -- oid (see https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier)
    local result = ""
    local i = 1
    if (len >= 1) then
        local firstByteVal = string.byte(string.sub(data,i,i))
        result = result .. math.floor(firstByteVal/40) .. "." .. (firstByteVal % 40)
        i = i + 1
        while (i <= len) do
            local n = 0
            repeat
                local byteVal = string.byte(string.sub(data,i,i))
                n = n * 128 + (0x7F & byteVal)
                i = i + 1
            until (byteVal <= 127 or i > len)
            result = result .. "." .. n
        end
    end
    return result
end

-- returns a string ip address from a 4 byte array
function decodeIPAddress(data, len)
    local result = nil
    if (len == 4) then
        result = string.format("%d.%d.%d.%d", 
        string.byte(string.sub(data,1,1)), 
        string.byte(string.sub(data,2,2)), 
        string.byte(string.sub(data,3,3)), 
        string.byte(string.sub(data,4,4)))
    elseif (len == 16) then
        -- ipv6, note we do not bother to compress by eliminating leading zeros and always show long-form
        result = logger.toHexString(string.sub(data,1,2)) .. ":" ..
            logger.toHexString(string.sub(data,3,4)) .. ":" ..
            logger.toHexString(string.sub(data,5,6)) .. ":" ..
            logger.toHexString(string.sub(data,7,8)) .. ":" ..
            logger.toHexString(string.sub(data,9,10)) .. ":" ..
            logger.toHexString(string.sub(data,11,12)) .. ":" ..
            logger.toHexString(string.sub(data,13,14)) .. ":" ..
            logger.toHexString(string.sub(data,15,16))
    end
    return result
end

-- returns a table with an encoded DN from a dirName field in SAN
-- the encoding format is a bit strange, but designed to mimic what jsrsasign does in the Infomap
-- version of the certeai. Some of the DN fields are labeled slightly differently by jsrsasign, so
-- inspect result["str"] and use it if you need to
function decodeDirName(berData)
    local result = { str = "", array={}}
    if (berData["type"] == 4 and berData["constructed"] == true and #berData["children"] == 1) then
        local dnSeq = berData["children"][1]
        if (dnSeq["type"] == 16 and dnSeq["constructed"] == true) then
            local dnstr = ""
            for k,v in pairs(dnSeq["children"]) do
                -- each element of the sequence should be a set with one sequence in it
                if (v["type"] == 17 and v["constructed"] == true and #v["children"] == 1) then
                    local segmentSeq = v["children"][1]
                    -- a segment sequence should have two elements - an oid and a value
                    if (segmentSeq["type"] == 16 and segmentSeq["constructed"] == true and #segmentSeq["children"] == 2) then
                        local segmentOID = segmentSeq["children"][1]
                        local segmentVal = segmentSeq["children"][2]
                        local oidStr = nil
                        local strVal = nil
                        local segObj = {}
                        if (segmentOID["type"] == 6) then
                            local oid = decodeOID(segmentOID["data"], segmentOID["length"])
                            oidStr = dnOIDTable[oid]
                            if (oidStr == nil) then
                                logger.debugLog("decodeDirName unknown dn component oid: " .. oid)
                                result = nil
                                break
                            end
                        else
                            logger.debugLog("decodeDirName segmentOID did not contain oid")
                            result = nil
                            break
                        end

                        -- might need to add others at some point
                        -- PrintableString or UTF8String or IA5String
                        if (segmentVal["type"] == 19 or segmentVal["type"] == 12 or segmentVal["type"] == 22) then
                            strVal = segmentVal["data"]
                        else
                            logger.debugLog("decodeDirName segmentVal did not contain string")
                            result = nil
                            break
                        end

                        dnstr = dnstr .. "/" .. oidStr .. "=" .. strVal
                        logger.debugLog("oidStr: " .. oidStr .. "=" .. strVal)
                        segObj["type"] = oidStr
                        segObj["ds"] = dsTable[segmentVal["type"]]
                        segObj["value"] = strVal
                        local segObjArray = {[1] = segObj}
                        table.insert(result["array"], segObjArray)
                    else
                        logger.debugLog("decodeDirName segmentSeq did not contain exactly 2 element seq")
                        result = nil
                        break
                    end
                else
                    logger.debugLog("decodeDirName dnSeq did not contain single element set")
                    result = nil
                    break
                end
            end
            if (result ~= nil) then
                result["str"] = dnstr
            end
        else
            logger.debugLog("decodeDirName invalid dnSeq")
            result = nil
        end
    else
        logger.debugLog("decodeDirName invalid berData")
        result = nil
    end
    return result
end

-- Decode the EDIPartyName field of a SAN
-- This was developed and tested using a sample cert found as an attachment to: https://bugzilla.mozilla.org/show_bug.cgi?id=233586
function decodeEDIPartyName(berData)
    --logger.debugLog("decodeEDIPartyName called with berData: " .. logger.dumpAsString(berData))
    local result = { str = "", array={}}
    if (berData["type"] == 5 and berData["constructed"] == true and #berData["children"] >= 1) then
        for k,v in pairs(berData["children"]) do
            -- each element of the sequence should be either nameAssigner (type=0) or partyName (type=1)
            if (v["type"] == 0 and v["constructed"] == false and v["data"] ~= nil) then
                result["array"]["nameAssigner"] = decodeDirectoryString(v["data"])
            elseif (v["type"] == 1 and v["constructed"] == false and v["data"] ~= nil) then
                result["array"]["partyName"] = decodeDirectoryString(v["data"])
            else
                result = nil
                logger.debugLog("decodeEDIPartyName invalid children in berData")
            end
        end
    else
        result = nil
        logger.debugLog("decodeEDIPartyName invalid berData")
    end
    if (result ~= nil) then
        result["str"] = cjson.encode(result["array"])
    end
    return result
end

-- decode CountryName
function decodeCountryName(berData)
    logger.debugLog("decodeCountryName called with berData: " .. logger.dumpAsString(berData))
    local result = {}

    -- can be a NumericString or PrintableString
    if ((berData["type"] == 18 or berData["type"] == 19) and berData["constructed"] == false and berData["data"] ~= nil) then
        local attrName = "x121-dcc-code"
        if (berData["type"] == 19) then
            attrName = "iso-3166-alpha2-code"
        end
        result[attrName] = berData["data"]
    else
        result = nil
        logger.debugLog("decodeCountryName invalid berData")
    end

    return result
end

-- decode AdministrationDomainName
function decodeAdministrationDomainName(berData)
    logger.debugLog("decodeAdministrationDomainName called with berData: " .. logger.dumpAsString(berData))
    local result = {}

    -- can be a NumericString or PrintableString
    if ((berData["type"] == 18 or berData["type"] == 19) and berData["constructed"] == false and berData["data"] ~= nil) then
        local attrName = "numeric"
        if (berData["type"] == 19) then
            attrName = "printable"
        end
        result[attrName] = berData["data"]
    else
        result = nil
        logger.debugLog("decodeAdministrationDomainName invalid berData")
    end

    return result
end

-- decodes BuiltInStandardAttributes
function decodeBuiltInStandardAttributes(berData)
    logger.debugLog("decodeBuiltInStandardAttributes called with berData: " .. logger.dumpAsString(berData))
        --[[
        {
            ["children"] = {
                [1] = {
                    ["children"] = {
                        [1] = {
                            ["constructed"] = false,
                            ["type"] = 19,
                            ["class"] = 0,
                            ["data"] = AU,
                            ["length"] = 2
                        }
                    },
                    ["constructed"] = true,
                    ["type"] = 1,
                    ["class"] = 1,
                    ["data"] = AU,
                    ["length"] = 4
                },
                
                [2] = {
                    ["children"] = {
                        [1] = {
                            ["constructed"] = false,
                            ["type"] = 19,
                            ["class"] = 0,
                            ["data"] = IBM,
                            ["length"] = 3
                        }
                    },
                    ["constructed"] = true,
                    ["type"] = 2,
                    ["class"] = 1,
                    ["data"] = IBM,
                    ["length"] = 5
                }
            },
            ["constructed"] = true,
            ["type"] = 16,
            ["class"] = 0,
            ["data"] = aAUbIBM,
            ["length"] = 13
        }		
        --]]
    local result = {}

    if (berData["type"] == 16 and berData["constructed"] == true and #berData["children"] >= 1) then
        for k,v in pairs(berData["children"]) do
            -- each element of the sequence needs to be detected

            -- is this CountryName
            if (v["class"] == 1 and v["type"] == 1 and v["constructed"] == true and #v["children"] == 1) then
                result["CountryName"] = decodeCountryName(v["children"][1])

            -- is this AdministrationDomainName
            elseif (v["class"] == 1 and v["type"] == 2 and v["constructed"] == true and #v["children"] == 1) then
                result["AdministrationDomainName"] = decodeAdministrationDomainName(v["children"][1])
            else
                -- ignore (just log) elements that we haven't written a decoder for
                logger.debugLog("decodeBuiltInStandardAttributes unrecognized sequence member: " .. logger.dumpAsString(v))
            end
        end
    else
        result = nil
        logger.debugLog("decodeBuiltInStandardAttributes invalid berData")
    end

    return result
end

-- Decode the x400Address field of a SAN
-- See definition of ORAddress in https://datatracker.ietf.org/doc/html/rfc5280
-- This was developed and tested using a sample cert from IBM GSKit team (Simon).
function decodeX400Address(berData)
    logger.debugLog("decodeX400Address called with berData: " .. logger.dumpAsString(berData))
    local result = {}
    if (berData["type"] == 3 and berData["constructed"] == true and #berData["children"] >= 1) then
        -- first child is BuiltInStandardAttributes
        result["builtInStandardAttributes"] = decodeBuiltInStandardAttributes(berData["children"][1])

        -- if there is a second element in the sequence, it will be BuiltInDomainDefinedAttributes
        --TODO - consider implementing this

        -- if there is a third element in the sequence, it will be ExtensionAttributes
        --TODO - consider implementing this
    else
        result = nil
        logger.debugLog("decodeX400Address invalid berData")
    end

    return result
end

--[[

Partially decodes the ASN1 SAN data from a certificate

Fields we aren't expecting are ignored


Example output (as JSON):
    {
        "array": [
            {
                "rfc822": "emailtest@us.ibm.com"
            },
            {
                "dns": "santest.example.lab"
            },
            {
                "ip": "192.168.1.124"
            },
            {
                "other": {
                    "value": {
                        "utf8str": {
                            "str": "user@example.net"
                        }
                    },
                    "oid": "1.3.6.1.5.5.7.8.5"
                }
            }
        ],
        "extname": "subjectAltName"
    }

]]--
function decodeSubjectAlternativeName(sanData)
    -- This encoding of result is (on purpose) designed to mimic
    -- what jsrsasign does in the AAC/Infomap based example of the 
    -- certificate EAI. You could change this to be whatever you like
    local result = {extname = "subjectAltName", array = {}}

    -- use the open source ber library to do the heavy lifting
    local decodeResult = ber.decode(sanData)

    -- now look through the decoded result for things we expect in a SAN
    if (decodeResult["class"] == 0 and decodeResult["constructed"] == true) then
        for k,v in pairs(decodeResult["children"]) do
            if (v["type"] == 1) then
                -- email address
                --logger.debugLog("email: " .. v["data"])
                table.insert(result["array"], {rfc822 = v["data"]})
            elseif (v["type"] == 2) then
                -- dns
                --logger.debugLog("dns: " .. v["data"])
                table.insert(result["array"], {dns = v["data"]})
            elseif (v["type"] == 7 and (v["length"] == 4 or v["length"] == 16)) then
                -- ip address
                local ip = decodeIPAddress(v["data"], v["length"])
                --logger.debugLog("ip: " .. ip)
                table.insert(result["array"], {ip = ip})
            elseif (v["type"] == 6) then
                -- uri
                --logger.debugLog("uri: " .. v["data"])
                table.insert(result["array"], {uri = v["data"]})
            elseif (v["type"] == 8) then
                -- rid
                local rid = decodeOID(v["data"], v["length"])
                --logger.debugLog("rid: " .. rid)
                table.insert(result["array"], {rid = rid})
            elseif (v["type"] == 4 and v["constructed"] == true) then
                -- dirName
                local dirName = decodeDirName(v)
                if (dirName ~= nil) then
                    logger.debugLog("dirName: " .. cjson.encode(dirName))
                    table.insert(result["array"], {dn = dirName})
                else
                    logger.debugLog("error decoding dirName - skipping")
                end
            elseif (v["type"] == 5 and v["constructed"] == true) then
                -- ediPartyName
                local ediPartyName = decodeEDIPartyName(v)
                if (ediPartyName ~= nil) then
                    logger.debugLog("ediPartyName: " .. cjson.encode(ediPartyName))
                    table.insert(result["array"], {ediPartyName = ediPartyName})
                else
                    logger.debugLog("error decoding ediPartyName - skipping")
                end
            elseif (v["type"] == 3 and v["constructed"] == true) then
                -- x400Address
                local x400Address = decodeX400Address(v)
                if (x400Address ~= nil) then
                    logger.debugLog("x400Address: " .. cjson.encode(x400Address))
                    table.insert(result["array"], {x400Address = x400Address})
                else
                    logger.debugLog("error decoding x400Address - skipping")
                end
            elseif (v["type"] == 0 and v["constructed"] == true) then
                local other = {}
                -- this is otherName
                for k2,v2 in pairs(v["children"]) do
                    if (v2["type"] == 6) then
                        -- oid
                        local oid = decodeOID(v2["data"], v2["length"])
                        --logger.debugLog("othername.oid: " .. oid)
                        other["oid"] = oid
                    elseif (v2["type"] == 0 and v2["constructed"] == true) then
                        local value = {}
                        -- this is an object with stuff in it - depends on the oid as to what it means
                        -- for our purposes we only care about a single element with a UTF8String in it
                        for k3,v3 in pairs(v2["children"]) do
                            -- this is somewhat hard-coded to expect what we want in our othername data
                            -- you could easily extend this section to deal with other arbitrary encoded
                            -- ASN1 data types depending on what your certificate encodes into othername
                            if (v3["type"] == 12) then
                                -- this is a UTF8String
                                local str = v3["data"]
                                --logger.debugLog("str: " .. str)
                                value["utf8str"] = { str = str}
                            else
                                logger.debugLog("decodeSubjectAlternativeName.othername.elem skipping unsupported type: " .. v3["type"] .. " with length: " .. v3["length"])
                            end
                        end
                        other["value"] = value
                    else
                        logger.debugLog("decodeSubjectAlternativeName.othername skipping unsupported type: " .. v2["type"] .. " with length: " .. v2["length"])
                    end
                end
                table.insert(result["array"], {other = other})
            else
                logger.debugLog("decodeSubjectAlternativeName skipping unsupported type: " .. v["type"] .. " with length: " .. v["length"])
            end
        end
    end

    --logger.debugLog("decodeSubjectAlternativeName: " .. cjson.encode(result))

    return result
end

function logSubjectAlternativeName(san)
    logger.debugLog("ocert.getExtension(\"2.5.29.17\"): " .. logger.dumpAsString(san))
    logger.debugLog("san.getName(): " .. san:getName())
    logger.debugLog("san.getShortName(): " .. san:getShortName())
    logger.debugLog("san.getLongName(): " .. san:getLongName())
    local sanData = san:getData()

    logger.debugLog("sanData.length(): " .. string.len(sanData))
    logger.debugLog("sanData.hex: " .. logger.toHexString(sanData))

    local parsedSANData = decodeSubjectAlternativeName(sanData)
    logger.debugLog("logSubjectAlternativeName: " .. cjson.encode(parsedSANData))
end

function getPrincipalNameFromSAN(san)
	local result = nil
	if (san ~= nil and san["array"] ~= nil) then
        local found = false
        for k,v in pairs(san["array"]) do
            if (v["other"] ~= nil and 
                v["other"]["oid"] ~= nil and 
                v["other"]["oid"] == "1.3.6.1.4.1.311.20.2.3" and
                v["other"]["value"] ~= nil and
                v["other"]["value"]["utf8str"] ~= nil and
                v["other"]["value"]["utf8str"]["str"] ~= nil) then
                result = v["other"]["value"]["utf8str"]["str"]
            end
        end
    end
	return result;
end


--[[
MAIN ENTRY POINT STARTS HERE
]]--


--logger.debugLog(logger.dumpAsString(Control.dumpContext()))

-- get the certificate from header
local cert = HTTPRequest.getHeader("cert")

-- test cert from for ediPartyName testing (https://bugzilla.mozilla.org/show_bug.cgi?id=233586)
--local cert = "MIICujCCAnagAwIBAgIBLDALBgcqhkjOOAQDBQAwKjELMAkGA1UEBhMCdXMxDDAKBgNVBAoTA3N1bjENMAsGA1UECxMEbGFiczAeFw0wNDAyMDkxOTQzNTJaFw0wNDAyMDkxOTQzNTJaMDsxCzAJBgNVBAYTAnVzMQwwCgYDVQQKEwNzdW4xDTALBgNVBAsTBGxhYnMxDzANBgNVBAMTBnlhc3NpcjCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCjrh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQBTDv+z0kqA4GEAAKBgA2SU4K/vPP3bSu89PY+wY9WCpXiXE0P48RS3kCW2xtyMDHD0jWNlXAwOoQtd1xMzDQLP7+rKNiS0DlXcFWYjVq8O6txdXDLBPdOV9jRfCqgmKSqKOOB3Kqbqq5ugNwW3Sfz9+aWdW10L4QNgjGClBFllH5tzZMHaZPAPcc9XKy7oxswGTAXBgNVHREEEDAOpQyBChMIZWRpUGFydHkwCwYHKoZIzjgEAwUAAzEAMC4CFQCNrkXreYTYZQdRbwP0CvtgVF7IfAIVAIaUd40H3/1qE9/Jt4ci+JYBYXz3"
-- test cert from for x400 name testing (https://bugzilla.mozilla.org/show_bug.cgi?id=233586)
--local cert = "MIICrzCCAm2gAwIBAgIBOjALBgcqhkjOOAQDBQAwKjELMAkGA1UEBhMCdXMxDDAKBgNVBAoTA3N1bjENMAsGA1UECxMEbGFiczAeFw0wNDAyMTAxODQ1MDlaFw0wNDAyMTAxODQ1MDlaMDsxCzAJBgNVBAYTAnVzMQwwCgYDVQQKEwNzdW4xDTALBgNVBAsTBGxhYnMxDzANBgNVBAMTBnlhc3NpcjCCAbcwggEsBgcqhkjOOAQBMIIBHwKBgQD9f1OBHXUSKVLfSpwu7OTn9hG3UjzvRADDHj+AtlEmaUVdQCJR+1k9jVj6v8X1ujD2y5tVbNeBO4AdNG/yZmC3a5lQpaSfn+gEexAiwk+7qdf+t8Yb+DtX58aophUPBPuD9tPFHsMCNVQTWhaRMvZ1864rYdcq7/IiAxmd0UgBxwIVAJdgUI8VIwvMspK5gqLrhAvwWBz1AoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9B4JnUVlXjrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCjrh4rs6Z1kW6jfwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQBTDv+z0kqA4GEAAKBgA2SU4K/vPP3bSu89PY+wY9WCpXiXE0P48RS3kCW2xtyMDHD0jWNlXAwOoQtd1xMzDQLP7+rKNiS0DlXcFWYjVq8O6txdXDLBPdOV9jRfCqgmKSqKOOB3Kqbqq5ugNwW3Sfz9+aWdW10L4QNgjGClBFllH5tzZMHaZPAPcc9XKy7oxIwEDAOBgNVHREEBzAFowMTAWEwCwYHKoZIzjgEAwUAAy8AMCwCFCVcuekcrfkp48dNrG+XMxQFZp1GAhQISBmfZLbT9/g9nw+ci2MkqbDa/w=="
-- test cert from for x400 name testing (from GSKit - Simon)
--local cert = "MIIFFzCCAv+gAwIBAgIUZHS2IBfR0kTxNj2UmE19NS0lSoswDQYJKoZIhvcNAQELBQAwDTELMAkGA1UEAwwCQ0EwHhcNMjQxMjAzMDM1NTQyWhcNMjUxMjAzMDM1NTQyWjANMQswCQYDVQQDDAJDQTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBANDjK/YNIqfOaCKX50q/Tcui++Nhgst/EpP8IMD6sxra0hWnZOHLE+gpQe1kc9Xc5Pj1Tbhn8iCv+h/OT4d4U3gdKX/BIHkLCl5xv6oGDw6C9eNp9khonRhZwTN8N2JH5epHbnRNfdfOBcYo7Tf0BMw9vzp0H6HDvVu8ncwO7ca5q+7h/aiMeg3p3DV2s+nHsyFveTVQKgnB/CEgHhmVLhutBLMm3n1ZsT42Dp0nCwISBzs0SkiIgjZuRw/sgl/auDEwj/TVzutOQbgNTTIAKJC+zaUoXXAMFEepqqp4Bsb+bf4M/4v9r+I4+XlUzDbh2Gf1dd2KOxiqmKCCWrq2wcB+hdl5FLapseO4994BoxRgpkWOAtiqTeFp8BrkoUMGAYaKfe7L0X8sxeqj3z0kW2HG/z4ueaUb/fXorb8haIzZaxUDGSzLFDGkVHA1gD2qNZVKVrT+3VOnYSlgVmy8sJqo88KF6u7ffWja/XkIGoi8HkmU6nOO2mWI3JYRlSJeurEoz0u4b6BPz4FIlKz0uQupXeRwJ11RftQGpgNiIlfcKEqaeAI25VtAAOVA5qgZPRjRQlC/yURvdI6Ypx4BA1AyvSpcaXxASw1gY5b5x56UAzzIj6B3TWcPp9fUACHUc7PfUV3PcYAvRql3yJ2ZuTUclj9R4HrhNy1XrAm63xk5AgMBAAGjbzBtMBoGA1UdEQQTMBGjDzANYQQTAkFVYgUTA0lCTTAuBgNVHR8EJzAlMCOgIaAfhh1odHRwOi8vbG9jYWxob3N0OjQ0NDQvY3JsLmNybDALBgNVHQ8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkqhkiG9w0BAQsFAAOCAgEAnZ5tUdVVN02pZ654wwKeWfmQ1kVqijPKGQwPEOhI8BN4qb75EEMhEJ5qonICGUy5vrvG4on+NDbUw+1bDIsb04u6ry3frTkG6FwC9S9KEtpXQgpLCx/IRoEeq5dK0Z7kR7hzTHemtQx608v1LpVejj55AYuWKS6a/7fosfKJS8MMEZ18dMJXei1KRpjg+w6+yNbAQUZBdscMAqmapvD+4hrSD0xjyjentPWmdk5lm+Xo0U4KT79XHLqtj4Yk++N9UOAbB67IqdpFGVlvWFs1wH2UakYMHWVHuwNYe034wu5kEoSWX4ylzuQpIXsMW54vK+k9m8z8u17cJur9KmW9P7bkrI11bNasiBm4ej2WVu6HRFYpx+rH3FkghFv0QVsmhntXiM5lIWRTNA0MwnlWjwbnMHpTUCOa+816dXR06CUD7s4xAAThxn34KHaBI52CupRSKJalH2vXenge6FTo9K98iPb6aDICLhW090RoF77x/qCApUqUxzvARHCGu/rHv7iLZ4dTUe8r7OBdtQxObZqLOxUc5X1e5gLA+ty5qRe+yO+9xf8Xhm0ov1Tukwp+x2klo7MqzpIIqqoyZiPnK6Ucx8oamQeI+0tmnPNAAP+/7XSNv/+52x/lMWETj1h7DYaIUwG5mDwvcBX9JoIinGn6CX1dvzOU2jcEt0VazPk="


local san = nil
local sanUPN = nil
if not cert then
    logger.debugLog("certificate header not found")
    errorResponse("no certificate header")
else
    --logger.debugLog("cert: " .. cert)
    local ocert = x509.new("-----BEGIN CERTIFICATE-----\n" .. cert .. "\n-----END CERTIFICATE-----\n", "PEM")
    --logger.debugLog("ocert.getExtensionCount(): " .. ocert:getExtensionCount())
    local subjectAltNameExtension = ocert:getExtension("2.5.29.17")
    if (subjectAltNameExtension ~= nil) then
        -- for debugging
        logSubjectAlternativeName(subjectAltNameExtension)
        san = decodeSubjectAlternativeName(subjectAltNameExtension:getData())
        sanUPN = getPrincipalNameFromSAN(san)
    end
end


-- Set the EAI response data.
-- If you want to map the user to something based on the SAN data, 
-- then take a look at the san object and extract from there or return an error.

if (san ~= nil and sanUPN ~= nil) then
    HTTPResponse.setStatusCode(200)
    HTTPResponse.setStatusMsg("OK")
    HTTPResponse.setHeader("am-eai-user-id", sanUPN)
    HTTPResponse.setHeader("am-eai-auth-level", "1")
    HTTPResponse.setHeader("am-eai-xattrs", "san")
    HTTPResponse.setHeader("san", cjson.encode(san))
    HTTPResponse.setBody('<html>This response should never be seen.</html>')
else
    errorResponse("Unable to find UPN in certificate")
end

Control.responseGenerated(true)
