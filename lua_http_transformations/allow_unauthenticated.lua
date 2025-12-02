--[[
        A HTTP transformation that skips the standard authorization decision for matching requests.
        to make the decision.

        Make SURE you only attach it for HTTP methods and resources that you want to allow through.
        The example below permits the OPTIONS call to the /app/info URL.

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        allow_unauthenticated = allow_unauthenticated.lua

        [http-transformations:allow_unauthenticated]
        request-match = preazn:OPTIONS /api/info *
        request-match = preazn:OPTIONS /api/form *

        =============

--]]
Authorization.setDecision("allow")
