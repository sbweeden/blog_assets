# PAC (Privilege Attribute Certificate) Structure Documentation

## Overview

A PAC (Privilege Attribute Certificate) is a security credential used in IBM Security Verify Access (formerly IBM Security Access Manager) to represent authenticated user identity, group memberships, and associated attributes. This document describes the complete structure of a PAC based on its ASN.1 encoding.

## High-Level Structure

A PAC header consists of:
1. **Magic Prefix** (4 bytes): `0x04 0x02 0xAC 0xDC`
2. **ASN.1 Encoded Principal Chain**: The actual credential data
3. **Base64 Encoding**: The entire structure is base64-encoded
4. **Optional Version Prefix**: May include `"Version=1, "` prefix

## ASN.1 Structure Definitions

### 1. Principal Chain (`ivprincipal_chain_t`)

The top-level structure containing the signature and list of principals.

```asn1
IVPrincipalChain ::= SEQUENCE {
    signature       UTF8String,
    principalList   SEQUENCE OF IVPrincipal
}
```

**Components:**
- `signature`: A UTF8String containing the signature (typically "SIGNATURE")
- `principalList`: A sequence containing one or more principals (typically just one)

---

### 2. Principal (`ivprincipal_t`)

Represents a single principal with authentication information and attributes.

```asn1
IVPrincipal ::= SEQUENCE {
    version             INTEGER,
    principalData       CHOICE {
        unauthenticated     INTEGER (0),
        authenticated       PrivilegeAttributes
    },
    authType            INTEGER,
    attributeList       [OPTIONAL] SEQUENCE {
        attributes          AttributeList
    }
}
```

**Components:**
- `version`: Version number (typically 1)
- `principalData`: Either:
  - `INTEGER 0` for unauthenticated principals
  - `PrivilegeAttributes` sequence for authenticated principals
- `authType`: Authentication type
  - `0` = Unauthenticated
  - `1` = Authenticated
- `attributeList`: Optional wrapper sequence containing the attribute list

**Structure Variations:**

**Unauthenticated Principal (3 elements):**
```
SEQUENCE {
    version         INTEGER (1),
    authType        INTEGER (0),
    attributeList   SEQUENCE {
        attributes      AttributeList
    }
}
```

**Authenticated Principal (4 elements):**
```
SEQUENCE {
    version             INTEGER (1),
    privilegeAttributes PrivilegeAttributes,
    authType            INTEGER (1),
    attributeList       SEQUENCE {
        attributes          AttributeList
    }
}
```

---

### 3. Privilege Attributes (`sec_id_pa_t`)

Contains the principal identity and group memberships.

```asn1
PrivilegeAttributes ::= SEQUENCE {
    principal   SecId,
    groups      SEQUENCE OF SecId
}
```

**Components:**
- `principal`: The principal's security identifier
- `groups`: A sequence of group security identifiers (may be empty)

---

### 4. Security Identifier (`sec_id_t`)

Basic structure for identifying principals and groups.

```asn1
SecId ::= SEQUENCE {
    uuid    UUID,
    name    [OPTIONAL] UTF8String
}
```

**Components:**
- `uuid`: UUID structure identifying the principal or group
- `name`: Optional UTF8String name

---

### 5. UUID (`uuid_t`)

Represents a UUID in structured format.

```asn1
UUID ::= SEQUENCE {
    timeLow                 INTEGER,        -- 32-bit
    timeMid                 INTEGER,        -- 16-bit
    timeHiAndVersion        INTEGER,        -- 16-bit
    clockSeqHiAndReserved   INTEGER,        -- 8-bit
    clockSeqLow             INTEGER,        -- 8-bit
    node                    OCTET STRING    -- 6 bytes (48-bit)
}
```

**UUID String Format:**
```
xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
timeLow-timeMid-timeHiAndVersion-clockSeqHi+clockSeqLow-node
```

**Example:**
- UUID String: `12345678-1234-5678-9abc-def012345678`
- ASN.1 Representation:
  - timeLow: `0x12345678`
  - timeMid: `0x1234`
  - timeHiAndVersion: `0x5678`
  - clockSeqHiAndReserved: `0x9a`
  - clockSeqLow: `0xbc`
  - node: `0xdef012345678` (6 bytes)

---

### 6. Attribute List (`attrlist_t`)

Contains named attributes with their values.

```asn1
AttributeList ::= SEQUENCE OF Attribute
```

---

### 7. Attribute (`attr_t`)

A single named attribute with one or more values.

```asn1
Attribute ::= SEQUENCE {
    name    UTF8String,
    values  SEQUENCE OF Value
}
```

**Components:**
- `name`: UTF8String attribute name (e.g., "AZN_CRED_PRINCIPAL_DOMAIN")
- `values`: Sequence of attribute values

**Common Attribute Names:**
- `AZN_CRED_PRINCIPAL_DOMAIN`: Principal's domain
- `AZN_CRED_REGISTRY_ID`: Registry identifier (e.g., DN)
- `AZN_CRED_AUTH_METHOD`: Authentication method used
- `AZN_CRED_BROWSER_INFO`: Browser information
- `AZN_CRED_IP_ADDRESS`: Client IP address

---

### 8. Value (`value_t`)

Represents a single attribute value.

```asn1
Value ::= SEQUENCE {
    valueType   INTEGER,
    utf8Value   UTF8String,
    byteValue   OCTET STRING
}
```

**Components:**
- `valueType`: Type of value
  - `4` = String value (most common)
  - Other types may exist but are not commonly used
- `utf8Value`: UTF8String containing the value (when valueType = 4)
- `byteValue`: OCTET STRING (typically empty for string values)

**Note:** Only string values (valueType = 4) are commonly used and decoded by the parser.

---

## Complete Structure Example

Here's a visual representation of a complete authenticated PAC:

```
PAC Header (Base64 encoded)
├── Magic Prefix: 0x04 0x02 0xAC 0xDC
└── IVPrincipalChain (SEQUENCE)
    ├── signature (UTF8String): "SIGNATURE"
    └── principalList (SEQUENCE)
        └── IVPrincipal[0] (SEQUENCE)
            ├── version (INTEGER): 1
            ├── PrivilegeAttributes (SEQUENCE)
            │   ├── principal (SecId - SEQUENCE)
            │   │   ├── uuid (UUID - SEQUENCE)
            │   │   │   ├── timeLow (INTEGER)
            │   │   │   ├── timeMid (INTEGER)
            │   │   │   ├── timeHiAndVersion (INTEGER)
            │   │   │   ├── clockSeqHiAndReserved (INTEGER)
            │   │   │   ├── clockSeqLow (INTEGER)
            │   │   │   └── node (OCTET STRING)
            │   │   └── name (UTF8String): "username"
            │   └── groups (SEQUENCE)
            │       ├── SecId[0] (SEQUENCE)
            │       │   ├── uuid (UUID - SEQUENCE)
            │       │   └── name (UTF8String): "group1"
            │       └── SecId[1] (SEQUENCE)
            │           ├── uuid (UUID - SEQUENCE)
            │           └── name (UTF8String): "group2"
            ├── authType (INTEGER): 1
            └── attributeList (SEQUENCE)
                └── AttributeList (SEQUENCE)
                    ├── Attribute[0] (SEQUENCE)
                    │   ├── name (UTF8String): "AZN_CRED_PRINCIPAL_DOMAIN"
                    │   └── values (SEQUENCE)
                    │       └── Value[0] (SEQUENCE)
                    │           ├── valueType (INTEGER): 4
                    │           ├── utf8Value (UTF8String): "Default"
                    │           └── byteValue (OCTET STRING): ""
                    └── Attribute[1] (SEQUENCE)
                        ├── name (UTF8String): "AZN_CRED_REGISTRY_ID"
                        └── values (SEQUENCE)
                            └── Value[0] (SEQUENCE)
                                ├── valueType (INTEGER): 4
                                ├── utf8Value (UTF8String): "cn=username,dc=example,dc=com"
                                └── byteValue (OCTET STRING): ""
```

---

## Unauthenticated Principal Structure

For unauthenticated principals, the structure is simplified:

```
IVPrincipal (SEQUENCE)
├── version (INTEGER): 1
├── authType (INTEGER): 0
└── attributeList (SEQUENCE)
    └── AttributeList (SEQUENCE)
        └── [attributes...]
```

**Predefined Values for Unauthenticated:**
- Principal name: `"unauthenticated"`
- Principal UUID: `"00000000-0000-0000-0000-000000000000"`
- Principal domain: `"Default"`
- Principal registryid: `"cn=unauthenticated"`

---

## Encoding Details

### Magic Prefix

Every PAC begins with a 4-byte magic prefix before the ASN.1 data:
```
0x04 0x02 0xAC 0xDC
```

This prefix is **not** part of the ASN.1 structure and must be stripped before ASN.1 decoding.

### Base64 Encoding

After the magic prefix and ASN.1 data are concatenated, the entire byte sequence is base64-encoded.

### Version Prefix

The base64-encoded PAC may be prefixed with:
```
Version=1, 
```

This prefix must be stripped before base64 decoding.

### Complete Encoding Process

1. Encode principal chain as ASN.1 DER
2. Prepend magic prefix: `0x04 0x02 0xAC 0xDC`
3. Base64 encode the result
4. Optionally prepend `"Version=1, "`

### Complete Decoding Process

1. Strip optional `"Version=1, "` prefix
2. Base64 decode
3. Verify and strip magic prefix (4 bytes)
4. ASN.1 DER decode the remaining bytes
5. Parse the principal chain structure

---

## ASN.1 Type Reference

The following ASN.1 types are used in PAC structures:

| ASN.1 Type | Tag | Description |
|------------|-----|-------------|
| INTEGER | 0x02 | Integer values (version, authType, valueType, UUID components) |
| OCTET STRING | 0x04 | Byte arrays (UUID node, empty byteValue) |
| UTF8String | 0x0C | Text strings (names, attribute values, signature) |
| SEQUENCE | 0x30 | Constructed sequences (all container structures) |

---

## Implementation Notes

### Integer Encoding

Integers in ASN.1 are encoded in big-endian format with the minimum number of bytes needed. If the high bit of the first byte is set (≥ 0x80), a leading zero byte is added to keep the value positive.

### UUID Encoding

UUIDs are encoded as 6 separate elements rather than a single byte string:
- 5 INTEGER elements (for the numeric components)
- 1 OCTET STRING element (for the 6-byte node)

### Attribute Values

While the `value_t` structure supports multiple value types, only string values (valueType = 4) are commonly used in practice. The `byteValue` field is typically an empty OCTET STRING for string values.

### Principal Chain

Although the structure supports multiple principals in a chain, typical implementations only include a single principal (the authenticated user).

---

## Security Considerations

1. **Signature Verification**: The signature field in the principal chain should be verified to ensure the PAC hasn't been tampered with.

2. **Magic Prefix Validation**: Always verify the magic prefix (`0x04 0x02 0xAC 0xDC`) before processing.

3. **ASN.1 Parsing**: Use a robust ASN.1 parser to prevent malformed data from causing security issues.

4. **Attribute Validation**: Validate attribute names and values to prevent injection attacks.

---

## References

- IBM Security Verify Access Documentation
- ASN.1 (Abstract Syntax Notation One) - ITU-T X.680
- DER (Distinguished Encoding Rules) - ITU-T X.690
- UUID Format - RFC 4122

---

## Appendix: Complete ASN.1 Module Definition

```asn1
PAC-Structures DEFINITIONS ::= BEGIN

IVPrincipalChain ::= SEQUENCE {
    signature       UTF8String,
    principalList   SEQUENCE OF IVPrincipal
}

IVPrincipal ::= SEQUENCE {
    version             INTEGER,
    principalData       CHOICE {
        unauthenticated     INTEGER (0),
        authenticated       PrivilegeAttributes
    },
    authType            INTEGER,
    attributeList       [OPTIONAL] SEQUENCE {
        attributes          AttributeList
    }
}

PrivilegeAttributes ::= SEQUENCE {
    principal   SecId,
    groups      SEQUENCE OF SecId
}

SecId ::= SEQUENCE {
    uuid    UUID,
    name    [OPTIONAL] UTF8String
}

UUID ::= SEQUENCE {
    timeLow                 INTEGER,
    timeMid                 INTEGER,
    timeHiAndVersion        INTEGER,
    clockSeqHiAndReserved   INTEGER,
    clockSeqLow             INTEGER,
    node                    OCTET STRING
}

AttributeList ::= SEQUENCE OF Attribute

Attribute ::= SEQUENCE {
    name    UTF8String,
    values  SEQUENCE OF Value
}

Value ::= SEQUENCE {
    valueType   INTEGER,
    utf8Value   UTF8String,
    byteValue   OCTET STRING
}

END
```

---

*This documentation was generated based on the CredParser.lua implementation for IBM Security Verify Access.*