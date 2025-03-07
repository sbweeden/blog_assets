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
