--
-- Lua implementation of CredParser for decoding iv-creds HTTP header values
-- Uses ber.lua as the ASN.1 decoder
--
-- This module provides a decodePACHeader function that parses PAC (Privilege Attribute Certificate)
-- headers and returns a structured table with principal, groups, and attributes.
--

local ber = require "ber"
local baseutils = require "basexx"

-- Module table
local CredParser = {}

-- Debug logging function (can be overridden)
local debugLog = function(s)
    -- Default: do nothing. Override this function to enable debug logging
    -- Example: debugLog = function(s) print("DEBUG: " .. s) end
end

-- Set custom debug logger
function CredParser.setDebugLogger(logger)
    debugLog = logger
end

--
-- Helper function to convert bytes to hex string
--
local function bytesToHexString(byteArray)
    return baseutils.to_hex(byteArray)
end

--
-- Helper function to extract integer from ASN.1 data
--
local function extractInteger(data)
    if #data == 0 then return 0 end
    local result = 0
    for i = 1, #data do
        result = (result << 8) | string.byte(data, i)
    end
    return result
end

--
-- Helper function to pad hex string to specified length
--
local function padHex(hexStr, length)
    local padding = string.rep("0", length)
    return string.sub(padding .. hexStr, -(length))
end

--
-- Unpacks the elements of a UUID in a PAC and constructs the UUID string
-- Corresponds to the struct uuid_t
--
local function decodeUUID(uuidSequence)
    local result = nil
    
    if uuidSequence and uuidSequence.type == ber.Types.SEQUENCE and 
       uuidSequence.children and #uuidSequence.children == 6 then
        
        -- Extract the 5 integer parts and 1 octet string
        local parts = {}
        for i = 1, 5 do
            if uuidSequence.children[i].type == ber.Types.INTEGER then
                local intVal = extractInteger(uuidSequence.children[i].data)
                parts[i] = intVal
            else
                debugLog("decodeUUID: Invalid integer at position " .. i)
                return nil
            end
        end
        
        -- The 6th element should be an octet string (node)
        if uuidSequence.children[6].type == ber.Types.OCTET_STRING then
            local nodeHex = bytesToHexString(uuidSequence.children[6].data)
            
            -- Format UUID: time_low-time_mid-time_hi_and_version-clock_seq_hi_and_reserved+clock_seq_low-node
            local gi1Hex = padHex(string.format("%x", parts[1]), 8)
            local gi2Hex = padHex(string.format("%x", parts[2]), 4)
            local gi3Hex = padHex(string.format("%x", parts[3]), 4)
            local gi4Hex = padHex(string.format("%x", parts[4]), 2)
            local gi5Hex = padHex(string.format("%x", parts[5]), 2)
            local nodeHexPadded = padHex(nodeHex, 12)
            
            result = gi1Hex .. "-" .. gi2Hex .. "-" .. gi3Hex .. "-" .. 
                     gi4Hex .. gi5Hex .. "-" .. nodeHexPadded
        else
            debugLog("decodeUUID: Invalid octet string for node")
        end
    else
        debugLog("decodeUUID: Invalid uuidSequence")
    end
    
    return result
end

--
-- Unpacks the basic structure used to identify principals and groups
-- Contains the UUID and an optional string name
-- Corresponds to the struct sec_id_t
--
local function decodeSecId(nameAndUUIDSequence)
    local result = nil
    
    if nameAndUUIDSequence.children and 
       (#nameAndUUIDSequence.children == 1 or #nameAndUUIDSequence.children == 2) then
        
        local uuid = decodeUUID(nameAndUUIDSequence.children[1])
        
        if uuid then
            result = { uuid = uuid }
            
            -- Check for optional name (UTF8String)
            if #nameAndUUIDSequence.children == 2 and 
               nameAndUUIDSequence.children[2].type == ber.Types.UTF8String then
                result.name = nameAndUUIDSequence.children[2].data
            end
        end
    else
        debugLog("decodeSecId: Invalid nameAndUUIDSequence")
    end
    
    return result
end

--
-- Unpacks a privilege attributes section of a PAC
-- Corresponds to the struct sec_id_pa_t
--
local function decodePrivilegeAttributes(principalAndGroupsSequence)
    local result = {
        Principal = {},
        GroupList = {}
    }
    
    if principalAndGroupsSequence.type == ber.Types.SEQUENCE and 
       principalAndGroupsSequence.children and 
       #principalAndGroupsSequence.children == 2 then
        
        -- First element: principal
        debugLog("decodePrivilegeAttributes: Parsing principal")
        local principalSequence = principalAndGroupsSequence.children[1]
        local principalObject = decodeSecId(principalSequence)
        
        if principalObject then
            debugLog("principalObject: " .. principalObject.uuid)
            result.Principal = principalObject
            
            -- Second element: groups
            debugLog("decodePrivilegeAttributes: Parsing groups")
            local groupsSequence = principalAndGroupsSequence.children[2]
            
            if groupsSequence.children then
                debugLog("decodePrivilegeAttributes: Number of groups: " .. #groupsSequence.children)
                
                for _, g in ipairs(groupsSequence.children) do
                    local groupObject = decodeSecId(g)
                    if groupObject then
                        table.insert(result.GroupList, groupObject)
                    else
                        debugLog("decodePrivilegeAttributes: Encountered invalid group")
                    end
                end
            end
        else
            debugLog("decodePrivilegeAttributes: Invalid Principal")
            result = nil
        end
    else
        debugLog("decodePrivilegeAttributes: Invalid principalAndGroupsSequence")
        result = nil
    end
    
    return result
end

--
-- Decodes attribute values
-- Corresponds to list of struct value_t
--
local function decodeAttributeValues(attributeValuesSequence)
    local result = {}
    
    if attributeValuesSequence and attributeValuesSequence.type == ber.Types.SEQUENCE then
        if attributeValuesSequence.children then
            for _, av in ipairs(attributeValuesSequence.children) do
                -- Each value should be a sequence of three: integer valuetype, string value, octet string
                if av.type == ber.Types.SEQUENCE and av.children and #av.children == 3 then
                    local valueTypeElement = av.children[1]
                    local utf8valElement = av.children[2]
                    local bytevalElement = av.children[3]
                    
                    -- Check if this is a string value (type 4)
                    if valueTypeElement.type == ber.Types.INTEGER then
                        local valueType = extractInteger(valueTypeElement.data)
                        
                        if valueType == 4 then
                            if utf8valElement.type == ber.Types.UTF8String then
                                table.insert(result, utf8valElement.data)
                            else
                                debugLog("decodeAttributeValues: Attribute value utf8val tag was not a string: " .. utf8valElement.type)
                            end
                        else
                            debugLog("decodeAttributeValues: Attribute value type was not a string: " .. valueType)
                        end
                    end
                    
                    -- Check byte values for non-empty octet string
                    if not (bytevalElement.type == ber.Types.OCTET_STRING and #bytevalElement.data == 0) then
                        debugLog("decodeAttributeValues: Attribute bytvalElement was not an empty octet-string. Type: " .. bytevalElement.type)
                        if bytevalElement.type == ber.Types.OCTET_STRING then
                            local bytevalHex = bytesToHexString(bytevalElement.data)
                            debugLog("decodeAttributeValues: Attribute bytvalElement content: " .. bytevalHex)
                        end
                    end
                else
                    debugLog("decodeAttributeValues: Invalid values sequence")
                end
            end
        end
    else
        debugLog("decodeAttributeValues: Invalid attributeValuesSequence")
    end
    
    return result
end

--
-- Decodes a single attribute
-- Corresponds to struct attr_t
--
local function decodeAttribute(attributeSequence)
    local result = { name = nil, values = {} }
    
    if attributeSequence and attributeSequence.type == ber.Types.SEQUENCE and 
       attributeSequence.children and #attributeSequence.children == 2 then
        
        -- First part: UTF8String attr name
        local asn1AttrName = attributeSequence.children[1]
        if asn1AttrName.type == ber.Types.UTF8String then
            result.name = asn1AttrName.data
            
            -- Second part: attribute values
            local attributeValuesArray = decodeAttributeValues(attributeSequence.children[2])
            if attributeValuesArray then
                result.values = attributeValuesArray
            else
                debugLog("decodeAttribute: Invalid attribute values")
            end
        else
            debugLog("decodeAttribute: Invalid attribute name")
        end
    else
        debugLog("decodeAttribute: Invalid attributeSequence")
    end
    
    return result
end

--
-- Decodes an attribute list
-- Corresponds to struct attrlist_t
--
local function decodeAttributeList(attributeListSequence)
    local result = {}
    
    if attributeListSequence and attributeListSequence.type == ber.Types.SEQUENCE then
        if attributeListSequence.children then
            for _, a in ipairs(attributeListSequence.children) do
                if a.type == ber.Types.SEQUENCE and a.children and #a.children == 2 then
                    local attributeObject = decodeAttribute(a)
                    if attributeObject and attributeObject.name then
                        result[attributeObject.name] = attributeObject.values
                    end
                else
                    debugLog("decodeAttributeList: Invalid attribute sequence")
                end
            end
        end
    else
        debugLog("decodeAttributeList: The attributeListSequence was invalid")
        result = nil
    end
    
    return result
end

--
-- Decodes a principal
-- Corresponds to struct ivprincipal_t
--
local function decodePrincipal(principalSequence)
    local result = {
        Version = nil,
        Principal = {},
        GroupList = {},
        AuthType = nil,
        AttributeList = {}
    }
    
    if principalSequence.type == ber.Types.SEQUENCE and principalSequence.children and
       (#principalSequence.children == 3 or #principalSequence.children == 4) then
        
        local firstElement = principalSequence.children[1]
        local secondElement = principalSequence.children[2]
        local thirdElement = principalSequence.children[3]
        local fourthElement = (#principalSequence.children > 3) and principalSequence.children[4] or nil
        local attributeListElement = nil
        
        -- Version element (should be integer)
        if firstElement.type == ber.Types.INTEGER then
            result.Version = tostring(extractInteger(firstElement.data))
            
            -- Check if unauthenticated (secondElement is integer 0)
            if secondElement.type == ber.Types.INTEGER then
                local authTypeVal = extractInteger(secondElement.data)
                
                if authTypeVal == 0 then
                    debugLog("This appears to be an unauthenticated cred")
                    result.AuthType = "0"
                    
                    -- Set canned values for unauthenticated principal
                    result.Principal.name = "unauthenticated"
                    result.Principal.uuid = "00000000-0000-0000-0000-000000000000"
                    result.Principal.domain = "Default"
                    result.Principal.registryid = "cn=unauthenticated"
                    
                    -- Check for attribute list in third element
                    if thirdElement.type == ber.Types.SEQUENCE and thirdElement.children and
                       #thirdElement.children == 1 and thirdElement.children[1].type == ber.Types.SEQUENCE then
                        attributeListElement = thirdElement.children[1]
                    else
                        debugLog("decodePrincipal: The credential was unauthenticated, but attribute list could not be found")
                    end
                end
            elseif secondElement.type == ber.Types.SEQUENCE and secondElement.children and
                   #secondElement.children == 2 then
                -- Authenticated credential - second element is principal and groups
                local principalAndGroupsObject = decodePrivilegeAttributes(secondElement)
                
                if principalAndGroupsObject then
                    result.Principal = principalAndGroupsObject.Principal
                    result.GroupList = principalAndGroupsObject.GroupList
                    
                    -- Third element should be authtype (integer 1 for authenticated)
                    if thirdElement.type == ber.Types.INTEGER then
                        result.AuthType = tostring(extractInteger(thirdElement.data))
                        
                        -- Fourth element contains attribute list
                        if fourthElement and fourthElement.type == ber.Types.SEQUENCE and
                           fourthElement.children and #fourthElement.children == 1 and
                           fourthElement.children[1].type == ber.Types.SEQUENCE then
                            attributeListElement = fourthElement.children[1]
                        end
                    else
                        debugLog("decodePrincipal: The thirdElement could not be decoded as authtype")
                        result = nil
                    end
                else
                    debugLog("decodePrincipal: The secondElement could not be decoded as principal and groups")
                    result = nil
                end
            else
                debugLog("decodePrincipal: The secondElement was not recognized")
                result = nil
            end
            
            -- Decode attribute list if present
            if result and attributeListElement then
                local attributeListObject = decodeAttributeList(attributeListElement)
                
                if attributeListObject then
                    result.AttributeList = attributeListObject
                    
                    -- Add domain and registryid to Principal from attributes
                    if attributeListObject["AZN_CRED_PRINCIPAL_DOMAIN"] and
                       #attributeListObject["AZN_CRED_PRINCIPAL_DOMAIN"] > 0 then
                        result.Principal.domain = attributeListObject["AZN_CRED_PRINCIPAL_DOMAIN"][1]
                    end
                    if attributeListObject["AZN_CRED_REGISTRY_ID"] and
                       #attributeListObject["AZN_CRED_REGISTRY_ID"] > 0 then
                        result.Principal.registryid = attributeListObject["AZN_CRED_REGISTRY_ID"][1]
                    end
                else
                    debugLog("decodePrincipal: Could not decode attributeListElement")
                    result = nil
                end
            end
        else
            debugLog("decodePrincipal: Invalid version element")
            result = nil
        end
    else
        debugLog("decodePrincipal: Invalid principalSequence")
        result = nil
    end
    
    return result
end

--
-- Decodes a principal chain
-- Corresponds to struct ivprincipal_chain_t
--
local function decodePrincipalChain(principalChainSequence)
    local result = {
        Signature = nil,
        PrincipalList = {}
    }
    
    if principalChainSequence.type == ber.Types.SEQUENCE and 
       principalChainSequence.children and #principalChainSequence.children == 2 then
        
        local signatureString = principalChainSequence.children[1]
        local principalSequence = principalChainSequence.children[2]
        
        -- First: signature (UTF8String)
        if signatureString and signatureString.type == ber.Types.UTF8String then
            result.Signature = signatureString.data
            
            -- Second: principal chain
            if principalSequence and principalSequence.type == ber.Types.SEQUENCE and
               principalSequence.children and #principalSequence.children > 0 then
                
                debugLog("decodePrincipalChain: Number of principals: " .. #principalSequence.children)
                local failedPrincipals = false
                
                for _, p in ipairs(principalSequence.children) do
                    local principalObject = decodePrincipal(p)
                    
                    if principalObject then
                        table.insert(result.PrincipalList, principalObject)
                    else
                        failedPrincipals = true
                    end
                end
                
                if failedPrincipals then
                    debugLog("decodePrincipalChain: One or more principals failed to decode")
                    result = nil
                end
            else
                debugLog("decodePrincipalChain: Invalid principal chain")
                result = nil
            end
        else
            debugLog("decodePrincipalChain: Invalid Signature")
            result = nil
        end
    else
        debugLog("decodePrincipalChain: Invalid principalChainSequence")
        result = nil
    end
    
    return result
end

--
-- Base64 decode function
--
local function base64Decode(input)
    return baseutils.from_base64(input)
end

--
-- Main function to decode PAC header
-- Given a string PAC header, decode to structured table (stsuu)
-- Only deals with the first principal in the chain
-- The pacHeader may include the "Version=1, " prefix - if found this will be stripped off
-- Only string values in the attribute list are returned
--
function CredParser.decodePACHeader(pacHeader)
    local stsuu = nil
    
    if pacHeader then
        stsuu = { Principal = {}, AttributeList = {}, GroupList = {} }
        
        -- PAC is base64 encoded with optional version prefix
        -- First 4 bytes are magic prefix, not part of credential chain ASN.1 sequence
        local success, err = pcall(function()
            local cleanHeader = string.gsub(pacHeader, "^Version=1, ", "")
            local credBytes = base64Decode(cleanHeader)
            
            if credBytes and #credBytes > 4 then
                -- Extract and validate prefix (4 bytes: 0x04 0x02 0xAC 0xDC)
                local b1, b2, b3, b4 = string.byte(credBytes, 1, 4)
                
                if b1 == 0x04 and b2 == 0x02 and b3 == 0xAC and b4 == 0xDC then
                    -- Remove prefix and decode the principal chain
                    local credData = string.sub(credBytes, 5)
                    local asn1PAC = ber.decode(credData)
                    
                    if asn1PAC then
                        local principalChainObject = decodePrincipalChain(asn1PAC)
                        
                        if principalChainObject and principalChainObject.PrincipalList and
                           #principalChainObject.PrincipalList > 0 then
                            stsuu = principalChainObject.PrincipalList[1]
                        else
                            debugLog("The PAC did not include at least one principal")
                            stsuu = nil
                        end
                    else
                        debugLog("Failed to decode ASN.1 structure")
                        stsuu = nil
                    end
                else
                    debugLog("The PAC prefix bytes are incorrect")
                    stsuu = nil
                end
            else
                debugLog("The PAC bytes are too short")
                stsuu = nil
            end
        end)
        
        if not success then
            debugLog("Exception parsing cred: " .. tostring(err))
            stsuu = nil
        end
    else
        debugLog("The PAC header string was not supplied")
    end
    
    return stsuu
end

-- Made with Bob


-- ============================================================================
-- ENCODING FUNCTIONS - Rebuild PAC headers from decoded structures
-- ============================================================================

--
-- Helper function to convert hex string to bytes
--
local function hexStringToBytes(hexStr)
    return baseutils.from_hex(hexStr)
end

--
-- Helper function to convert integer to bytes for ASN.1 encoding
--
local function integerToBytes(num)
    if num == 0 then return "" end
    local bytes = {}
    while num > 0 do
        table.insert(bytes, 1, num & 0xFF)
        num = num >> 8
    end
    return string.char(table.unpack(bytes))
end

--
-- Helper to encode an integer as ASN.1 INTEGER with proper byte representation
--
local function encodeInteger(num)
    if num == 0 then
        return {
            type = ber.Types.INTEGER,
            data = string.char(0)
        }
    end
    
    -- Convert number to bytes (big-endian)
    local bytes = {}
    local n = num
    while n > 0 do
        table.insert(bytes, 1, n & 0xFF)
        n = n >> 8
    end
    
    -- Add leading zero byte if high bit is set (to keep it positive)
    if bytes[1] >= 0x80 then
        table.insert(bytes, 1, 0)
    end
    
    local byteStr = string.char(table.unpack(bytes))
    
    return {
        type = ber.Types.INTEGER,
        data = byteStr
    }
end

--
-- Encodes a UUID string back to ASN.1 structure
-- Corresponds to the struct uuid_t
--
local function encodeUUID(uuidStr)
    if not uuidStr then return nil end
    
    -- Parse UUID string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    local parts = {}
    for part in string.gmatch(uuidStr, "[^-]+") do
        table.insert(parts, part)
    end
    
    if #parts ~= 5 then
        debugLog("encodeUUID: Invalid UUID format")
        return nil
    end
    
    -- Convert hex parts to integers
    local time_low = tonumber(parts[1], 16)
    local time_mid = tonumber(parts[2], 16)
    local time_hi_and_version = tonumber(parts[3], 16)
    local clock_seq = parts[4]  -- This is 4 hex chars (2 bytes)
    local clock_seq_hi = tonumber(string.sub(clock_seq, 1, 2), 16)
    local clock_seq_low = tonumber(string.sub(clock_seq, 3, 4), 16)
    local node = hexStringToBytes(parts[5])
    
    -- Build ASN.1 sequence with 6 elements using proper integer encoding
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = {
            encodeInteger(time_low),
            encodeInteger(time_mid),
            encodeInteger(time_hi_and_version),
            encodeInteger(clock_seq_hi),
            encodeInteger(clock_seq_low),
            {
                type = ber.Types.OCTET_STRING,
                data = node
            }
        }
    }
end

--
-- Encodes a sec_id_t structure (principal or group identifier)
--
local function encodeSecId(secId)
    if not secId or not secId.uuid then
        debugLog("encodeSecId: Invalid secId")
        return nil
    end
    
    local children = { encodeUUID(secId.uuid) }
    
    -- Add optional name if present
    if secId.name then
        table.insert(children, {
            type = ber.Types.UTF8String,
            data = secId.name
        })
    end
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = children
    }
end

--
-- Encodes privilege attributes (principal and groups)
-- Corresponds to the struct sec_id_pa_t
--
local function encodePrivilegeAttributes(principal, groupList)
    if not principal then
        debugLog("encodePrivilegeAttributes: Invalid principal")
        return nil
    end
    
    local principalSeq = encodeSecId(principal)
    if not principalSeq then return nil end
    
    -- Encode groups
    local groupChildren = {}
    if groupList then
        for _, group in ipairs(groupList) do
            local groupSeq = encodeSecId(group)
            if groupSeq then
                table.insert(groupChildren, groupSeq)
            end
        end
    end
    
    local groupsSeq = {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = groupChildren
    }
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = { principalSeq, groupsSeq }
    }
end

--
-- Encodes attribute values
-- Corresponds to list of struct value_t
--
local function encodeAttributeValues(values)
    if not values then return {} end
    
    local children = {}
    for _, value in ipairs(values) do
        -- Each value is a sequence of: valuetype (4 for string), utf8 value, empty octet string
        table.insert(children, {
            type = ber.Types.SEQUENCE,
            constructed = true,
            children = {
                encodeInteger(4),  -- valuetype for string
                {
                    type = ber.Types.UTF8String,
                    data = value
                },
                {
                    type = ber.Types.OCTET_STRING,
                    data = ""
                }
            }
        })
    end
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = children
    }
end

--
-- Encodes a single attribute
-- Corresponds to struct attr_t
--
local function encodeAttribute(name, values)
    if not name then
        debugLog("encodeAttribute: Invalid attribute name")
        return nil
    end
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = {
            {
                type = ber.Types.UTF8String,
                data = name
            },
            encodeAttributeValues(values or {})
        }
    }
end

--
-- Encodes an attribute list
-- Corresponds to struct attrlist_t
--
local function encodeAttributeList(attributeList)
    if not attributeList then return nil end
    
    local children = {}
    for name, values in pairs(attributeList) do
        local attrSeq = encodeAttribute(name, values)
        if attrSeq then
            table.insert(children, attrSeq)
        end
    end
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = children
    }
end

--
-- Encodes a principal
-- Corresponds to struct ivprincipal_t
--
local function encodePrincipal(principal)
    if not principal then
        debugLog("encodePrincipal: Invalid principal")
        return nil
    end
    
    local version = tonumber(principal.Version) or 1
    local authType = tonumber(principal.AuthType) or 1
    
    local children = { encodeInteger(version) }
    
    -- Check if unauthenticated
    if authType == 0 then
        -- Unauthenticated: version, authtype (0), attribute list wrapper
        table.insert(children, encodeInteger(0))
        
        local attrList = encodeAttributeList(principal.AttributeList or {})
        if attrList then
            table.insert(children, {
                type = ber.Types.SEQUENCE,
                constructed = true,
                children = { attrList }
            })
        end
    else
        -- Authenticated: version, principal+groups, authtype, attribute list wrapper
        local privAttrs = encodePrivilegeAttributes(principal.Principal, principal.GroupList)
        if not privAttrs then
            debugLog("encodePrincipal: Failed to encode privilege attributes")
            return nil
        end
        
        table.insert(children, privAttrs)
        table.insert(children, encodeInteger(authType))
        
        local attrList = encodeAttributeList(principal.AttributeList or {})
        if attrList then
            table.insert(children, {
                type = ber.Types.SEQUENCE,
                constructed = true,
                children = { attrList }
            })
        end
    end
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = children
    }
end

--
-- Encodes a principal chain
-- Corresponds to struct ivprincipal_chain_t
--
local function encodePrincipalChain(signature, principalList)
    if not signature or not principalList or #principalList == 0 then
        debugLog("encodePrincipalChain: Invalid parameters")
        return nil
    end
    
    local principalChildren = {}
    for _, principal in ipairs(principalList) do
        local principalSeq = encodePrincipal(principal)
        if principalSeq then
            table.insert(principalChildren, principalSeq)
        else
            debugLog("encodePrincipalChain: Failed to encode a principal")
            return nil
        end
    end
    
    return {
        type = ber.Types.SEQUENCE,
        constructed = true,
        children = {
            {
                type = ber.Types.UTF8String,
                data = signature
            },
            {
                type = ber.Types.SEQUENCE,
                constructed = true,
                children = principalChildren
            }
        }
    }
end

--
-- Base64 encode function
--
local function base64Encode(input)
    return baseutils.to_base64(input)
end

--
-- Main function to encode a PAC header from a decoded structure
-- Takes a principal structure (as returned by decodePACHeader) and rebuilds the PAC header
-- Returns a base64-encoded PAC header string WITHOUT the "Version=1, " prefix so that
-- it can be used directly as an EAI response header.
--
function CredParser.encodePACHeader(stsuu, signature)
    if not stsuu then
        debugLog("encodePACHeader: No principal structure provided")
        return nil
    end
    
    -- Default signature if not provided
    signature = signature or "SIGNATURE"
    
    -- Wrap the principal in a principal list (we only support single principal encoding)
    local principalList = { stsuu }
    
    -- Encode the principal chain
    local principalChainSeq = encodePrincipalChain(signature, principalList)
    if not principalChainSeq then
        debugLog("encodePACHeader: Failed to encode principal chain")
        return nil
    end
    
    -- Encode to ASN.1 DER
    local success, asn1Data = pcall(function()
        return ber.encode(principalChainSeq)
    end)
    
    if not success or not asn1Data then
        debugLog("encodePACHeader: Failed to encode ASN.1: " .. tostring(asn1Data))
        return nil
    end
    
    -- Add magic prefix: 0x04 0x02 0xAC 0xDC
    local prefix = string.char(0x04, 0x02, 0xAC, 0xDC)
    local pacBytes = prefix .. asn1Data
    
    -- Base64 encode and add version prefix
    local base64Pac = base64Encode(pacBytes)
    --return "Version=1, " .. base64Pac
    return base64Pac
end

return CredParser
