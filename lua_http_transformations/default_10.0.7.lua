--[[

This is a template which can be used as a guide when writing Lua scripts
for WebSEAL's HTTP Transformation engine. 

For detailed information on Lua scripting refer to the Lua reference
manual: https://www.lua.org/manual/5.4/.

To help protect the integrity of the appliance the following functions from
the Lua standard libraries have been disabled:
    - Basic:
        - loadfile
    - Operating System Facilities:
        - execute
        - exit
        - remove
        - setlocale
        - tmpname
    - Input and Output:
        - [ all functions ]
    - Package:
        - loadlib

The following Lua modules have also been preinstalled and are available when
writing transformation rules:
    - basexx (https://luarocks.org/modules/aiq/basexx)
    - binaryheap (https://luarocks.org/modules/tieske/binaryheap)
    - cqueues (https://luarocks.org/modules/daurnimator/cqueues)
    - urlencode (https://luarocks.org/modules/moznion/urlencode)
    - fifo (https://luarocks.org/modules/daurnimator/fifo)
    - http (https://luarocks.org/modules/daurnimator/http)
    - lpeg (https://luarocks.org/modules/gvvaughan/lpeg)
    - lpeg_patterns (https://luarocks.org/modules/daurnimator/lpeg_patterns)
    - luaossl (https://luarocks.org/modules/daurnimator/luaossl)
    - luasocket (https://luarocks.org/modules/luasocket/luasocket)
    - lua-cjson (https://luarocks.org/modules/openresty/lua-cjson)
    - redis-lua (https://luarocks.org/modules/nrk/redis-lua)

HTTP transformations can be managed using the following custom in-built Verify 
Access modules:

    - HTTPRequest
      This module allows you to manage the HTTP request.  The prototypes of the
      functions provided by this module are as follows:
        - Headers:
            boolean containsHeader(string name)
            table getHeaderNames()
            string getHeader(string name)
            nil setHeader(string name, string value)
            nil removeHeader(string name)
            nil clearHeaders()
        - Cookies:
            boolean containsCookie(string name)
            table getCookieNames()
            string getCookie(string name)
            nil setCookie(string name, string value)
            nil removeCookie(string name)
            nil clearCookies()
        - Body:
            string getBody()
            nil setBody(String body)
            number getContentLength()
        - Request Line:
            string getMethod()
            nil setMethod(string method)
            string getURL()
            nil setURL(string url)
            string getVersion()
            nil setVersion(string version)
            number getProtocol()

    - HTTPResponse
      This module allows you to manage the HTTP response.  The prototypes of 
      the functions provided by this module are as follows:
        - Headers:
            boolean containsHeader(string name)
            table getHeaderNames()
            string getHeader(string name)
            nil setHeader(string name, string value)
            nil removeHeader(string name)
            nil clearHeaders()
        - Cookies:
            boolean containsCookie(string name)
            table getCookieNames()
            string getCookie(string name)
            nil setCookie(string name, string value)
            nil removeCookie(string name)
            nil clearCookies()
        - Body:
            string getBody()
            nil setBody(String body)
            number getContentLength()
        - Response Line:
            string getVersion()
            number getStatusCode()
            nil setStatusCode(number code)
            string getStatusMsg()
            nil setStatusMsg(string msg)

    - Client
      This module allows you to access details about the HTTP client.
        - Sundry:
            string getIPAddress()
            string getCertificateField(string field)

    - Session
      This module allows you to access details of the current user session.
      The user session information will not be available for request triggers.
        - Sundry:
            string getSessionId()
            string getUsername()
            boolean containsCredentialAttribute(string name)
            string getCredentialAttribute(string name)
            table  getMvCredentialAttribute(string name)
            nil setCredentialAttribute(string name, string/array value)
            string getSessionAttribute(string name)
            nil setSessionAttribute(string name, string value)

    - Control
      This module allows you to control the processing of the request by 
      WebSEAL.
        - Authorization:
            nil setObjectName(string objectName)
            nil setAclBits(string aclBits)
        - Sundry:
            nil includeInRequestLog(boolean includeInLog)
            nil trace(number level, string message)
            nil returnErrorPage(string message)
            nil responseGenerated(boolean generated)
            string getConfig(string stanza, string entry)

    - Authorization
      This module allows you to create your own authorization decision logic.
      It is only valid when used in the preazn stage.
        - Sundry:
            nil setDecision(string decision, bool audit, table attributes)
            nil setReauth(boolean required)
            nil setAuthLevel(number level)
            nil setDisableCache(boolean disable)
            nil setCompressResponse(boolean compress)
            nil setStreamResponse(boolean stream)
            nil setStreamRequest(boolean stream)
            nil setDisableAudit(boolean disabled)
            nil setPreserveInactivity(boolean preserve)

    - Authentication
      This module allows you to specify authentication information which will
      be used by the EAI authentication module to generate a new session.  It
      is only valid when used in the postazn stage.
        - Sundry:
            nil setUserIdentity(string identity, boolean isExternal)
            nil setAuthLevel(number level)
            nil addGroup(string|array name)
            nil setAttribute(string name, string|array value)
            nil setRedirectURL(string url)

A simple HTTP transformation rule to add a header to the HTTP response 
would be:

    HTTPResponse.setHeader("rsp-header", "value")

Further details on the HTTP transformation support can be found in the
official IBM documentation for IBM Security Verify Access:
    - https://www.ibm.com/docs/en/sva/10.0.4?topic=junctions-http-transformations

--]]

