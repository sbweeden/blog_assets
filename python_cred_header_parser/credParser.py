# imports
import base64
import asn1
import json
import traceback

def credParserDebug(s):
    print(s)

def hexBytes(b):
    return ''.join('{:02x}'.format(x) for x in b)


#
# unpacks the elements of a UUID in a PAC and constructs the UUID string
# corresponds to the struct uuid_t
#
def decodeUUID(decoder):
    result = ""
    decoder.enter()
    decodingError = False
    #
    # extract integer parts of the UUID as bytes and convert to hex strings, taking into account that the first integer should be 8 hex chars
    # the second should be 4 chars, the third should be 4 chars, and the 4th and 5th are two chars
    # note that for gi4Hex and gi5Hex we expect these to be two hex chars so slice to that
    #
    # The portions of the UUID are:
    # time_low
    # time_mid
    # time_hi_and_version
    # clock_seq_hi_and_reserved
    # clock_seq_low
    # node (6 bytes)
    # 

    # time_low
    nextTag = decoder.peek()
    if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
        t, v = decoder.read()
        result = result + hexBytes(v.to_bytes(4, byteorder='big', signed=True))
    else:
        credParserDebug("decodeUUID: time_low not integer: " + str(nextTag))
        decodingError = True

    # time_mid
    if (not decodingError):
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
            t, v = decoder.read()
            result = result + "-" + hexBytes(v.to_bytes(2, byteorder='big', signed=True))
        else:
            credParserDebug("decodeUUID: time_mid not integer: " + str(nextTag))
            decodingError = True

    # time_hi_and_version
    if (not decodingError):
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
            t, v = decoder.read()
            result = result + "-" + hexBytes(v.to_bytes(2, byteorder='big', signed=True))
        else:
            credParserDebug("decodeUUID: time_hi_and_version not integer: " + str(nextTag))
            decodingError = True

    # clock_seq_hi_and_reserved
    if (not decodingError):
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
            t, v = decoder.read()
            result = result + "-" + (hexBytes(v.to_bytes(2, byteorder='big', signed=True))[-2:])
        else:
            credParserDebug("decodeUUID: clock_seq_hi_and_reserved not integer: " + str(nextTag))
            decodingError = True

    # clock_seq_low
    if (not decodingError):
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
            t, v = decoder.read()
            result = result + (hexBytes(v.to_bytes(2, byteorder='big', signed=True))[-2:])
        else:
            credParserDebug("decodeUUID: clock_seq_low not integer: " + str(nextTag))
            decodingError = True

    # node
    if (not decodingError):
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.OctetString):
            t, v = decoder.read()
            result = result + "-" + (("000000000000" + hexBytes(v))[-12:])
        else:
            credParserDebug("decodeUUID: node not octet_string: " + str(nextTag))
            decodingError = True

    # and that should be it
    if (not decodingError):
        if (decoder.peek() != None):
            credParserDebug("decodeUUID: There appears to be extra data after the node element")
            decodingError = True

    decoder.leave()

    if (decodingError):
        result = None
    return result

#
# unpacks the basic structure used to identify principals and groups
# it contains the UUID and an optional string name 
# corresponds to the struct sec_id_t
#
def decodeSecId(decoder):
    result = json.loads('{}')
    decodingError = False
    nextTag = decoder.peek()
    # should be a sequence of one or two things
    if (nextTag != None and nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()
        
        # first should be the uuid sequence
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.Sequence):
            uuidObject = decodeUUID(decoder)
            if (uuidObject != None):
                result["uuid"] = uuidObject

                # check if there is another element - if there is it should be a string name
                nextTag = decoder.peek()
                if (nextTag != None):
                    if (nextTag.nr == asn1.Numbers.UTF8String):
                        t, v = decoder.read()
                        result["name"] = v
                        # and that should be it
                        if (decoder.peek() != None):
                            credParserDebug("decodeSecId: There appears to be extra data after the name element")
                            decodingError = True
                    else:
                        credParserDebug("decodeSecId: name element was not a string: " + str(nextTag))
                        decodingError = True
            else:
                credParserDebug("decodeSecId: UUID element could not be decoded")
                decodingError = True
        else:
            credParserDebug("decodeSecId: UUID element a sequence: " + str(nextTag))
            decodingError = True

        decoder.leave()
    else:
        credParserDebug("decodeSecId: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    return result

#
# unpacks a privilege attributes section of a PAC
# corresponds to the struct sec_id_pa_t
#
def decodePrivilegeAttributes(decoder):
    result = json.loads('{ "Principal": {},  "GroupList": [] }')
    decodingError = False
    nextTag = decoder.peek()
    # should be a sequence of two (principal then groups), even if no groups
    if (nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()

        # first should be the principal
        nextTag = decoder.peek()
        if (nextTag.nr == asn1.Numbers.Sequence):
            principalObject = decodeSecId(decoder)
            if (principalObject != None):
                result["Principal"] = principalObject

                # next should be the groups (even if no groups)
                nextTag = decoder.peek()
                if (nextTag.nr == asn1.Numbers.Sequence):

                    # this sequence is actually a list of groups (i.e. a sequence of sequence)
                    decoder.enter()
                    nextTag = decoder.peek()
                    while (nextTag != None and not decodingError):
                        groupObject = decodeSecId(decoder)
                        if (groupObject != None):
                            result["GroupList"].append(groupObject)
                        else:
                            credParserDebug("decodePrivilegeAttributes: groups element could not be decoded")
                            decodingError = True

                        nextTag = decoder.peek()
                        if (nextTag != None and nextTag.nr != asn1.Numbers.Sequence):
                            credParserDebug("decodePrivilegeAttributes: An element in the groups sequence was not a sequence: " + str(nextTag))
                            decodingError = True
                    decoder.leave()
                else:
                    credParserDebug("decodePrivilegeAttributes: groups element not a sequence: " + str(nextTag))
                    decodingError = True
            else:
                credParserDebug("decodePrivilegeAttributes: principal element could not be decoded")
                decodingError = True

        decoder.leave()
    else:
        credParserDebug("decodePrivilegeAttributes: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    return result


#
# decodes an individual attribute value
# corresponds to subset of struct value_t 
#
def decodeAttributeValue(attrName, decoder):
    result = None
    decodingError = False
    nextTag = decoder.peek()
    if (nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()

        # first part is value type integer
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
            t, vValueType = decoder.read()
        
            # next part should be the string value
            nextTag = decoder.peek()
            if (nextTag != None and nextTag.nr == asn1.Numbers.UTF8String):
                t, vUTF8Val = decoder.read()

                # next part should be the octet string value
                nextTag = decoder.peek()
                if (nextTag != None and nextTag.nr == asn1.Numbers.OctetString):
                    t, vByteVal = decoder.read()

                    # and that should be it
                    if (decoder.peek() != None):
                        credParserDebug("decodeAttributeValue: There appears to be extra data after the byteval")
                        decodingError = True

                    if (not decodingError):
                        # process what we have discovered, subject to what types this method supports
                        # note that we ignore non-string values, but do log them
                        if (vValueType == 4):
                            result = vUTF8Val
                        else:
                            credParserDebug("decodeAttributeValue: WARNING - ignoring unexpected value type: " + vValueType)

                        # if we got any octet string bytes, print them too
                        if (len(vByteVal) > 0):
                            credParserDebug("decodeAttributeValue: WARNING - AttributeName: " + attrName + " ignoring binary attribute value: " + hexBytes(vByteVal))

                else:
                    credParserDebug("decodeAttributeValue: byteval type not OctetString: " + str(nextTag))
                    decodingError = True

            else:
                credParserDebug("decodeAttributeValue: utf8val type not UTF8String: " + str(nextTag))
                decodingError = True
            
        
        else:
            credParserDebug("decodeAttributeValue: value type not an integer: " + str(nextTag))
            decodingError = True

        decoder.leave()
    else:
        credParserDebug("decodeAttributeValue: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    return result

#
# decodes attribute values
# corresponds to list of struct value_t 
#
def decodeAttributeValues(attrName, decoder):
    result = json.loads('[]')
    decodingError = False
    nextTag = decoder.peek()
    if (nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()

        # each value is a sequence
        nextTag = decoder.peek()
        while (nextTag != None and not decodingError):

            attributeValue = decodeAttributeValue(attrName, decoder)

            # if its None, then chances are its an unsuported type, so just ignore
            if (attributeValue != None):
                result.append(attributeValue)

            nextTag = decoder.peek()
            if (nextTag != None and nextTag.nr != asn1.Numbers.Sequence):
                credParserDebug("decodeAttributeValues: An element in the attribute values sequence was not a sequence: " + str(nextTag))
                decodingError = True

        decoder.leave()
    else:
        credParserDebug("decodeAttributeValues: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    return result

#
# decodes a single attribute
# corresponds to struct attr_t
#
def decodeAttribute(decoder):
    result = json.loads('{"name": null, "values":[]}')
    decodingError = False
    nextTag = decoder.peek()
    if (nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()
        # first part should be the UTF8String attr name
        nextTag = decoder.peek()
        if (nextTag != None and nextTag.nr == asn1.Numbers.UTF8String):
            t, v = decoder.read()
            result["name"] = v

            # second part should be the sequence of values
            nextTag = decoder.peek()
            if (nextTag != None and nextTag.nr == asn1.Numbers.Sequence):
                attributeValuesArray = decodeAttributeValues(result["name"], decoder)
                if (attributeValuesArray != None):
                    result["values"] = attributeValuesArray
                    # and that shoud be it
                    if (decoder.peek() != None):
                        credParserDebug("decodeAttribute: There appears to be extra data after the attribute values")
                        decodingError = True
                else:
                    credParserDebug("decodeAttribute: Attribute values could not be decoded")
                    decodingError = True
            else:
                credParserDebug("decodeAttribute: Attribute values not a sequence: " + str(nextTag))
                decodingError = True
        else:
            credParserDebug("decodeAttribute: Attribute name not a string: " + str(nextTag))
            decodingError = True
        decoder.leave()
    else:
        credParserDebug("decodeAttribute: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    return result


#
# decodes an attribute list
# corresponds to struct attrlist_t
#
def decodeAttributeList(decoder):
    result = json.loads('{}')
    decodingError = False
    nextTag = decoder.peek()
    if (nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()
        # should contain one sequence which is the attribute list
        nextTag = decoder.peek()
        if (nextTag.nr == asn1.Numbers.Sequence):
            decoder.enter()
            # each attribute is a sequence
            nextTag = decoder.peek()
            while (nextTag != None and not decodingError):
                attributeObject = decodeAttribute(decoder)
                if (attributeObject != None):
                    result[attributeObject["name"]] = attributeObject["values"]
                else:
                    credParserDebug("decodeAttributeList: attribute element could not be decoded")
                    decodingError = True

                nextTag = decoder.peek()
                if (nextTag != None and nextTag.nr != asn1.Numbers.Sequence):
                    credParserDebug("decodeAttributeList: An element in the attributes sequence was not a sequence: " + str(nextTag))
                    decodingError = True
            decoder.leave()
        else:
            credParserDebug("decodeAttributeList: Subsequence not a sequence: " + str(nextTag))
            decodingError = True
            
        decoder.leave()
    else:
        credParserDebug("decodeAttributeList: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    return result



#
# decodes a principal
# corresponds to struct ivprincipal_t
#
def decodePrincipal(decoder):
    result = json.loads('{ "Version": null, "Principal": {},  "GroupList": [], "AuthType": null, "AttributeList": {} }')
    decodingError = False
    nextTag = decoder.peek()
    if (nextTag.nr == asn1.Numbers.Sequence):
        decoder.enter()

        # should be a sequence of three (if unauthenticated) or four elements (authenticated PAC)
        nextTag = decoder.peek()

        # the first element should always be version - an integer
        if (nextTag.nr == asn1.Numbers.Integer):
            t, v = decoder.read()
            result["Version"] = v
        else:
            credParserDebug("decodePrincipal: Version not an integer: " + str(nextTag))
            decodingError = True

        isUnauthenticated = False
        if (not decodingError):
            # next element should be either an integer (0) for unauthenticated PAC, or the principals and groups sequence
            nextTag = decoder.peek()
            if (nextTag.nr == asn1.Numbers.Integer):
                t, v = decoder.read()
                if (v == 0):
                    result["AuthType"] = v
                    isUnauthenticated = True
                    # also put some canned values in the unauthenticated principal
                    result["Principal"]["name"] = "unauthenticated"
                    result["Principal"]["uuid"] = "00000000-0000-0000-0000-000000000000"
                    result["Principal"]["domain"] = "Default"
                    result["Principal"]["registryid"] = "cn=unauthenticated"

                else:
                    credParserDebug("decodePrincipal: second element was integer but not 0" + str(v))
                    decodingError = True
            elif (nextTag.nr == asn1.Numbers.Sequence):
                principalAndGroupsObject = decodePrivilegeAttributes(decoder)
                if (principalAndGroupsObject != None):
                    result["Principal"] = principalAndGroupsObject["Principal"]
                    result["GroupList"] = principalAndGroupsObject["GroupList"]
                else:
                    credParserDebug("decodePrincipal: The secondElement could not be decoded as principal and groups")
                    decodingError = True
            else:
                credParserDebug("decodePrincipal: second element is not integer or sequence: " + str(nextTag))
                decodingError = True


        if (not decodingError):
            # next element depends on whether the credential is authenticated or not
            # if it is not (i.e. unauthenticated) then the next element should be the attribute list sequence
            # if it is authenticated, then the next element should be the integer authtype, and the one after that should be the attribute list sequence
            nextTag = decoder.peek()
            if (isUnauthenticated):
                if (nextTag != None and nextTag.nr == asn1.Numbers.Sequence):
                    attributeListObject = decodeAttributeList(decoder)
                    if (attributeListObject != None):
                        result["AttributeList"] = attributeListObject
                        # that should be it for this sequence
                        if (decoder.peek() != None):
                            credParserDebug("decodePrincipal: There appears to be extra data after the attribute list for an unauthenticated credential")
                            decodingError = True
                    else:
                        credParserDebug("decodePrincipal: Could not decode the attribute list for an unauthenticated credential")
                        decodingError = True
                else:
                    credParserDebug("decodePrincipal: cred is unauthenticated but third element is not sequence: " + str(nextTag))
                    decodingError = True

            else:
                # authenticated pac - next tag should be the authtype number, and the one after that should be the attribute list sequence
                if (nextTag != None and nextTag.nr == asn1.Numbers.Integer):
                    t, v = decoder.read()
                    result["AuthType"] = v
                    
                    nextTag = decoder.peek()
                    if (nextTag != None and nextTag.nr == asn1.Numbers.Sequence):
                        attributeListObject = decodeAttributeList(decoder)
                        if (attributeListObject != None):
                            result["AttributeList"] = attributeListObject
                            # that should be it for this sequence
                            if (decoder.peek() != None):
                                credParserDebug("decodePrincipal: There appears to be extra data after the attribute list for an authenticated credential")
                                decodingError = True
                        else:
                            credParserDebug("decodePrincipal: Could not decode the attribute list for an authenticated credential")
                            decodingError = True
                    else:
                        credParserDebug("decodePrincipal: cred is authenticated but fourth element is not sequence: " + str(nextTag))
                        decodingError = True
                else:
                    credParserDebug("decodePrincipal: cred is authenticated but third element is not authtype integer: " + str(nextTag))
                    decodingError = True

        # done with the principal sequence
        decoder.leave()
    else:
        credParserDebug("decodePrincipal: Not a sequence: " + str(nextTag))
        decodingError = True

    if (decodingError):
        result = None
    
    return result

#
# decodes a principal chain
# corresponds to struct ivprincipal_chain_t
# 
def decodePrincipalChain(decoder):
    result = json.loads('{ "Signature": null, "PrincipalList": [] }')
    tPrincipalChain = decoder.peek()
    # should be a sequence of two - signature then principal chain
    if (tPrincipalChain.nr == asn1.Numbers.Sequence):
        decoder.enter()

        # first the signature
        tSignature, vSignature = decoder.read()
        if (tSignature.nr == asn1.Numbers.UTF8String):
            result["Signature"] = vSignature

            # now the principal chain
            tPrincipalSequence = decoder.peek()
            # should be a sequence
            if (tPrincipalSequence.nr == asn1.Numbers.Sequence):
                decoder.enter()
                tPrincipal = decoder.peek()
                decodingError = False
                while (tPrincipal != None and not decodingError):
                    # is this a sequence like it should be?
                    if (tPrincipal.nr == asn1.Numbers.Sequence):
                        principal = decodePrincipal(decoder)
                        # should never be None
                        if (principal != None):
                            result["PrincipalList"].append(principal)
                        else:
                            credParserDebug("decodePrincipalChain: Principal decoding error")
                            decodingError = True
                        # look at the next element
                        tPrincipal = decoder.peek()
                    else:
                        credParserDebug("decodePrincipalChain: Invalid object in principal sequence" + str(tPrincipal))
                        decodingError = True
                decoder.leave()
            else:
                credParserDebug("decodePrincipalChain: Invalid principal chain")
        else:
            credParserDebug("decodePrincipalChain: Invalid Signature")
        decoder.leave()
    else:
        credParserDebug("decodePrincipalChain: Invalid principalChainSequence")
        result = None
    return result

#
# This is the main function to consume.
#
# Given a string PAC header, decode to JSON stsuu
# This does not account for every possible valid PAC - it only deals with the first principal in the chain, and also deals with unauthenticated PAC
# The pacHeader may include the "Version=1, " prefix - if found this will be stripped off
# Only string values in the attribute list are returned
#
#
def decodePACHeader(pacHeader):
    stsuu = None
    #credParserDebug("decodePACHeader start: " + pacHeader)
    if (pacHeader != None):
        try:
            # base64 decode the BAK.. string
            credBytes = base64.b64decode(pacHeader.replace("Version=1, ", ""))

            if (credBytes != None and  len(credBytes) > 4):

                # validate the prefix - historically, this is the four bytes 0x04 (length) 0x02 (version) 0xAC 0xDC (magic value)
                credPrefix = credBytes[:4]
                if (credPrefix == b"\x04\x02\xAC\xDC"):
                    # decode the principal
                    # credParserDebug("Decoding: " + hexBytes(credBytes[4:]))
                    decoder = asn1.Decoder()
                    decoder.start(credBytes[4:])
                    principalChainObject = decodePrincipalChain(decoder)
                    if (principalChainObject != None and principalChainObject["PrincipalList"] != None and len(principalChainObject["PrincipalList"]) > 0):
                        stsuu = principalChainObject["PrincipalList"][0]
                    else:
                        credParserDebug("The PAC did not include at least one principal")
                else:
                    credParserDebug("The PAC prefix bytes are incorrect")
            else:
                credParserDebug("The PAC bytes are too short")
        except:
            print(traceback.format_exc())
            credParserDebug("Exception parsing credential")
    else:
        credParserDebug("The PAC header string was not supplied")

    return stsuu
