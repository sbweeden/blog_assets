-- Echos back the current request in YAML format such 
-- that it might then be used with the offline testing tool
HTTPResponse.setHeader("content-type", "text/plain")
HTTPResponse.setBody(Control.dumpContext())
HTTPResponse.setStatusCode(200)
HTTPResponse.setStatusMsg("OK")
Control.responseGenerated(true)
