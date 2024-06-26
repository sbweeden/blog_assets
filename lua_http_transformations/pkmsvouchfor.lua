--[[
        A HTTP transformation that further restricts (subdomain) redirects for ECSSO - where subdomain is insufficient.
        
        ECSSO Kickoff URL looks like:
            https://<MAS HOST>.<ECSSO Domain>/pkmsvouchfor?company1&https://somewhere.<ECSSO Domain>/
        
        Activated in Reverse Proxy on the MAS host - with:

        ================
        [http-transformations]
         
        pkmsvouchfor = pkmsvouchfor.lua
        #
        # The [http-transformations:<resource-name>] stanza is used to house
        # configuration which is specific to a particular HTTP transformation resource.
        #
         
        [http-transformations:pkmsvouchfor]
        request-match = request:GET /pkmsvouchfor*

        =============
        
        Update the 'acceptedHostnames' list below to the accepted redirect hosts. 
        This could also be modified to blacklist some hosts - and leave it more open. 
        Currently redirects back to "/" with an error param. Send this to your desired location, 
        or provide a complete error response body. 
        
--]]


function validateURL()
    -- Get the URL from the HTTP request
    local url = HTTPRequest.getURL()

    -- Pattern to extract the last part of the URL after the last '&'
    -- Order of parameters are important for pkmsvouchfor
    -- Its not really a traditional query string parameter
    local pattern = "https://([^/&]+)"

    -- Extract the last URL component
    local lastParam = url:match(pattern)

    -- Define the accepted hostnames
    local acceptedHostnames = {
        ["somewhere.demo.local"] = true,
        ["another.demo.local"] = true  -- You can add more accepted hostnames here
    }

    -- Check if the extracted hostname is in the list of accepted hostnames
    if lastParam and acceptedHostnames[lastParam] then
        print("Hostname is accepted.")
        return true
    else
        print("Hostname is not accepted.")
        return false
    end
end

-- Check the new password against the prohibited list
if not validateURL() then
    HTTPResponse.setStatusCode(302)
    HTTPResponse.setStatusMsg("Found")
    HTTPResponse.setHeader("Location", "/?error=invalidredir")
    HTTPResponse.setBody('<html>Invalid Request</html>')
    Control.responseGenerated(true)
end