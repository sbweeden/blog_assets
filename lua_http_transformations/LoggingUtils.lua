--[[
Simple logging utilities
--]]
local LoggingUtils = {}

function LoggingUtils.dumpAsString(o)
    if type(o) == 'table' then
       local s = '{'
       local first = true
       for k,v in pairs(o) do
          if not first then
            s = s .. ','
          end
          first = false
          if type(k) ~= 'number' then k = '"'..k..'"' end
          s = s .. '['..k..'] = ' .. LoggingUtils.dumpAsString(v)
       end
       return s .. '}'
    else
       return tostring(o)
    end
end

function LoggingUtils.debugLog(s)
   print(s)
--   Control.trace(9, s)
end

function LoggingUtils.toHexString(s)
   local res = ''
   for i = 1, #s do
      res = res .. string.format("%02x", string.byte(string.sub(s,i,i)))
   end
   return res
end

return LoggingUtils
