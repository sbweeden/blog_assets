--[[
Simple HTML utilities
--]]

local HTMLUtils = {}

--
-- Performs html encoding of a string
--
function htmlEncode(str)
    if str == nil then
        return nil
    end
    
    -- Replace HTML special characters with their entity equivalents
    local html_entities = {
        ["&"] = "&amp;",
        ["<"] = "&lt;",
        [">"] = "&gt;",
        ['"'] = "&quot;",
        ["'"] = "&#39;"
    }
    
    return (str:gsub("[&<>\"']", html_entities))
end

-- Performs html decoding of a string
function htmlDecode(str)
    if str == nil then
        return nil
    end
    
    -- Replace HTML entities with their original characters
    local html_entities = {
        ["&amp;"] = "&",
        ["&lt;"] = "<",
        ["&gt;"] = ">",
        ["&quot;"] = '"',
        ["&#39;"] = "'"
    }

    return (str:gsub("&(%a+);", html_entities))
end

return HTMLUtils