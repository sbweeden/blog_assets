--[[
        A HTTP transformation that removes all cookies from inbound requests.

        The example below shows it applied to POST requests of the ISVA token endpoint

        Activated in Reverse Proxy config with:

        ================
        [http-transformations]
        remove_all_cookies = remove_all_cookies.lua

        [http-transformations:remove_all_cookies]
        request-match = request:POST /mga/sps/oauth/oauth20/token*

        =============

--]]
HTTPRequest.clearCookies()

