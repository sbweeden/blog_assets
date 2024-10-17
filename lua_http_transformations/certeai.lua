--[[
        A transformation that unpacks an X509 certificate for the purposes of it being used as a certificate EAI

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        certeai = certeai.lua

        [http-transformations:certeai]
        request-match = request:POST /certeai *
        =============
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
                    table.insert(result["array"], { dn = dirName})
                else
                    logger.debugLog("error decoding dirName - skipping")
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

    decodeSubjectAlternativeName(sanData)
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
