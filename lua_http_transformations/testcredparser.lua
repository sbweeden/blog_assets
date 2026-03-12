--[[
        A HTTP transformation that is used to exercise the credparser

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        testcredparser = testestcredparsertjwk.lua

        [http-transformations:testcredparser]
        request-match = request:GET /testcredparser *
        =============

        Then in a browser just https://yourwebseal.com/testcredparser
--]]
local logger = require 'LoggingUtils'
local credParser = require "CredParser"
local cjson = require 'cjson'

function preBlockWithTitle(title, text)
    return "<div style='border: 1px solid black; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end

function errorBlockWithTitle(title, text)
    return "<div style='border: 1px solid red; padding: 10px; margin: 10px;'>" .. title .. "<br/><pre>" .. text .. "</pre></div>"
end


logger.debugLog("testcredparser")

local rspBody = "<html><body>"

credParser.setDebugLogger(logger.debugLog)

-- unauthenticated
local unauthenticatedPAC = "Version=1, BAKs3DCCA70MADCCA7cwggOzAgIQBgIBADCCA6gwggOkMC8MGEFaTl9DUkVEX0FVVEhfRVBPQ0hfVElNRTATMBECAQQMCjE2OTExMzU3ODAEADCBlwwVQVpOX0NSRURfQlJPV1NFUl9JTkZPMH4wfAIBBAx1TW96aWxsYS81LjAgKE1hY2ludG9zaDsgSW50ZWwgTWFjIE9TIFggMTBfMTVfNykgQXBwbGVXZWJLaXQvNTM3LjM2IChLSFRNTCwgbGlrZSBHZWNrbykgQ2hyb21lLzExNS4wLjAuMCBTYWZhcmkvNTM3LjM2BAAwJgwSQVpOX0NSRURfSVBfRkFNSUxZMBAwDgIBBAwHQUZfSU5FVAQAMCsMEEFaTl9DUkVEX01FQ0hfSUQwFzAVAgEEDA5JVl9VTkFVVEhfVjMuMAQAMDMMHEFaTl9DUkVEX05FVFdPUktfQUREUkVTU19CSU4wEzARAgEEDAoweGMwYTgwMTc2BAAwNgwcQVpOX0NSRURfTkVUV09SS19BRERSRVNTX1NUUjAWMBQCAQQMDTE5Mi4xNjguMS4xMTgEADAtDBlBWk5fQ1JFRF9QUklOQ0lQQUxfRE9NQUlOMBAwDgIBBAwHRGVmYXVsdAQAMDMMF0FaTl9DUkVEX1BSSU5DSVBBTF9OQU1FMBgwFgIBBAwPdW5hdXRoZW50aWNhdGVkBAAwLQwRQVpOX0NSRURfUU9QX0lORk8wGDAWAgEEDA9TU0s6IFRMU1YxMjogMkYEADAuDBJBWk5fQ1JFRF9VU0VSX0lORk8wGDAWAgEEDA91bmF1dGhlbnRpY2F0ZWQEADAnDBBBWk5fQ1JFRF9WRVJTSU9OMBMwEQIBBAwKMHgwMDAwMTAwNgQAMDQMGHRhZ3ZhbHVlX2xvZ2luX3VzZXJfbmFtZTAYMBYCAQQMD3VuYXV0aGVudGljYXRlZAQAMEcMFnRhZ3ZhbHVlX3Nlc3Npb25faW5kZXgwLTArAgEEDCQ2NjJiNDZiZS0zMjljLTExZWUtODA1YS0wMDBjMjk2YzI5ZDUEADCBqQwYdGFndmFsdWVfdXNlcl9zZXNzaW9uX2lkMIGMMIGJAgEEDIGBYkc5allXeG9iM04wTFdSbFptRjFiSFFBX1pNeXZKQUFBQUFJQUFBQXdKSy9NWkFpRkFreUhmd0FBVWxVelV6UTFkbEpTWjNoUVZWWlJNWEpDTUZKaFRuQXRWSFZ1WmxSMGJXeHpPR3c1UzA0NU5GRkpXVzVhWjBaVjpkZWZhdWx0BAA="
local unauthenticatedPACTable = credParser.decodePACHeader(unauthenticatedPAC)
rspBody = rspBody .. preBlockWithTitle("Unauthenticated", logger.dumpAsString(unauthenticatedPACTable) .. '\nJSON: ' .. cjson.encode(unauthenticatedPACTable))

-- testuser
local testuserPAC = "Version=1, BAKs3DCCBugMADCCBuIwggbeAgIQBjCBgjAqMB4CBOmjO5ACAhriAgIR7gICAKYCAgDMBAYADClsKdUMCHRlc3R1c2VyMFQwKDAeAgQkN22cAgIyfQICEe4CAgCmAgIAzAQGAAwpbCnVDAZncm91cDEwKDAeAgQqTgd8AgIyfQICEe4CAgCmAgIAzAQGAAwpbCnVDAZncm91cDICAQEwggZOMIIGSjAiDBRBVVRIRU5USUNBVElPTl9MRVZFTDAKMAgCAQQMATEEADAxDBdBWk5fQ1JFRF9BVVRITk1FQ0hfSU5GTzAWMBQCAQQMDUxEQVAgUmVnaXN0cnkEADAzDBJBWk5fQ1JFRF9BVVRIWk5fSUQwHTAbAgEEDBRjbj10ZXN0dXNlcixkYz1pc3dnYQQAMC8MGEFaTl9DUkVEX0FVVEhfRVBPQ0hfVElNRTATMBECAQQMCjE2OTE2MzQ5MTEEADApDBRBWk5fQ1JFRF9BVVRIX01FVEhPRDARMA8CAQQMCHBhc3N3b3JkBAAwgZcMFUFaTl9DUkVEX0JST1dTRVJfSU5GTzB+MHwCAQQMdU1vemlsbGEvNS4wIChNYWNpbnRvc2g7IEludGVsIE1hYyBPUyBYIDEwXzE1XzcpIEFwcGxlV2ViS2l0LzUzNy4zNiAoS0hUTUwsIGxpa2UgR2Vja28pIENocm9tZS8xMTUuMC4wLjAgU2FmYXJpLzUzNy4zNgQAMDEMD0FaTl9DUkVEX0dST1VQUzAeMA0CAQQMBmdyb3VwMQQAMA0CAQQMBmdyb3VwMgQAMFUMG0FaTl9DUkVEX0dST1VQX1JFR0lTVFJZX0lEUzA2MBkCAQQMEmNuPWdyb3VwMSxkYz1pc3dnYQQAMBkCAQQMEmNuPWdyb3VwMixkYz1pc3dnYQQAMHIMFEFaTl9DUkVEX0dST1VQX1VVSURTMFowKwIBBAwkMjQzNzZkOWMtMzI3ZC0xMWVlLWE2Y2MtMDAwYzI5NmMyOWQ1BAAwKwIBBAwkMmE0ZTA3N2MtMzI3ZC0xMWVlLWE2Y2MtMDAwYzI5NmMyOWQ1BAAwJgwSQVpOX0NSRURfSVBfRkFNSUxZMBAwDgIBBAwHQUZfSU5FVAQAMCkMEEFaTl9DUkVEX01FQ0hfSUQwFTATAgEEDAxJVl9MREFQX1YzLjAEADAzDBxBWk5fQ1JFRF9ORVRXT1JLX0FERFJFU1NfQklOMBMwEQIBBAwKMHhjMGE4MDE3NwQAMDYMHEFaTl9DUkVEX05FVFdPUktfQUREUkVTU19TVFIwFjAUAgEEDA0xOTIuMTY4LjEuMTE5BAAwLQwZQVpOX0NSRURfUFJJTkNJUEFMX0RPTUFJTjAQMA4CAQQMB0RlZmF1bHQEADAsDBdBWk5fQ1JFRF9QUklOQ0lQQUxfTkFNRTARMA8CAQQMCHRlc3R1c2VyBAAwSAwXQVpOX0NSRURfUFJJTkNJUEFMX1VVSUQwLTArAgEEDCRlOWEzM2I5MC0xYWUyLTExZWUtYTZjYy0wMDBjMjk2YzI5ZDUEADAtDBFBWk5fQ1JFRF9RT1BfSU5GTzAYMBYCAQQMD1NTSzogVExTVjEyOiAyRgQAMDUMFEFaTl9DUkVEX1JFR0lTVFJZX0lEMB0wGwIBBAwUY249dGVzdHVzZXIsZGM9aXN3Z2EEADAfDBJBWk5fQ1JFRF9VU0VSX0lORk8wCTAHAgEEDAAEADAnDBBBWk5fQ1JFRF9WRVJTSU9OMBMwEQIBBAwKMHgwMDAwMTAwNgQAMDAMDGVtYWlsQWRkcmVzczAgMB4CAQQMF3Rlc3R1c2VyQG1haWxpbmF0b3IuY29tBAAwIwwMbW9iaWxlTnVtYmVyMBMwEQIBBAwKMDQxMjM0MTIzNAQAMC0MGHRhZ3ZhbHVlX2xvZ2luX3VzZXJfbmFtZTARMA8CAQQMCHRlc3R1c2VyBAAwNgwkdGFndmFsdWVfbWF4X2NvbmN1cnJlbnRfd2ViX3Nlc3Npb25zMA4wDAIBBAwFdW5zZXQEADBHDBZ0YWd2YWx1ZV9zZXNzaW9uX2luZGV4MC0wKwIBBAwkODAwMjM5NzQtMzcyNi0xMWVlLTgwNWEtMDAwYzI5NmMyOWQ1BAAwgakMGHRhZ3ZhbHVlX3VzZXJfc2Vzc2lvbl9pZDCBjDCBiQIBBAyBgWJHOWpZV3hvYjNOMExXUmxabUYxYkhRQV9aTlJNM3dBQUFBSUFBQUF3MzB6VVpKakREa3lIZndBQVRqTTJOVWRYWW1sSk4wUXpOWFJ0WVZsSFIweGFOMjVMUWpkT2VsZDJhR2gzYmpJdFYzVllOakJRTlVKd2RDdGE6ZGVmYXVsdAQA"
local testuserPACTable = credParser.decodePACHeader(testuserPAC)
rspBody = rspBody .. preBlockWithTitle("testuser", logger.dumpAsString(testuserPACTable) .. '\nJSON: ' .. cjson.encode(testuserPACTable))

-- add an attribute to the testuser pac
testuserPACTable["AttributeList"]["new_attribute"] = { "new_value" }
testuserPACTable["AttributeList"]["new_attribute_mv"] = { "new_value1", "new_value2" }
local newtestuserPAC = credParser.encodePACHeader(testuserPACTable)
rspBody = rspBody .. preBlockWithTitle("testuser with attributes added", logger.dumpAsString(testuserPACTable) .. '\nJSON: ' .. cjson.encode(testuserPACTable) .. '\nPAC: ' .. newtestuserPAC)

-- decode the new PAC
local newtestuserPACTable = credParser.decodePACHeader(newtestuserPAC)
rspBody = rspBody .. preBlockWithTitle("decoded testuser with attributes added", logger.dumpAsString(newtestuserPACTable) .. '\nJSON: ' .. cjson.encode(newtestuserPACTable))


rspBody = rspBody .. "</body></html>"

HTTPResponse.setHeader("content-type", "text/html")
HTTPResponse.setBody(rspBody)
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)

