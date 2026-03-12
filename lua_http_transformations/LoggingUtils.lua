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
   elseif type(o) == 'string' then
      -- check if every char is printable
      -- if it is, return the string otherwise return a hex string
      local isPrintable = true
      for i = 1, #o do
         local c = string.byte(string.sub(o,i,i))
         if c < 32 or c > 126 then
            isPrintable = false
            break
         end
      end
      if isPrintable then
         return o
      else
         return 'ByteString[' .. LoggingUtils.toHexString(o) .. ']'
      end
   elseif type(o) == 'function' then
      return 'Function[]'
   else
      return tostring(o)
   end
end

function LoggingUtils.debugLog(s)
   print(s)
--   Control.trace(9, s)
end

function LoggingUtils.toHexString(s)
   return (s:gsub('.', function(c)
        return string.format('%02x', string.byte(c))
    end))
end

function LoggingUtils.dumpRequest()
	local result = ''
	result = result .. 'RequestLine: ' .. HTTPRequest.getMethod() .. ' ' .. HTTPRequest.getURL() .. '\n'
	result = result .. 'Start Headers\n'
	for k,v in pairs(HTTPRequest.getHeaderNames()) do
		result = result .. v .. ': ' .. HTTPRequest.getHeader(v) .. '\n'
	end
	result = result .. 'End Headers\n'
	result = result .. 'Start Cookies\n'
	for k,v in pairs(HTTPRequest.getCookieNames()) do
		result = result .. v .. '=' .. HTTPRequest.getCookie(v) .. '\n'
	end
	result = result .. 'End Cookies\n'
	result = result .. 'Start body\n'
	local b = HTTPRequest.getBody()
	if (b ~= nil) then
		result = result .. b .. '\n'
	end
	result = result .. 'End body\n'
	
	LoggingUtils.debugLog(result)
end

return LoggingUtils
