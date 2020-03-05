<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	version="1.0" xmlns:external="http://xsltfunctions.isam.ibm.com">

 <!--
 	Used to add cors response headers to permit cross-origin discovery of authenticated users
 	
 	Configure as a response http transformation with something like:
 	
 	[http-transformations]
 	cors-response-headers = cors-response-headers.xsl
 	
 	[http-transformations:cors-response-headers]
 	request-match = response:GET /mga/sps/apiauthsvc/policy/amiauthenticated*

  -->

	<!-- Firstly, strip any space elements -->
	<xsl:strip-space elements="*" />


	<!--
	  Perform a match on the root of the document. Output the required
	  HTTPResponseChange elements.
	-->
	<xsl:template match="/">
	  <HTTPResponseChange>
	    <Header name="Access-Control-Allow-Origin" action="add">https://idp.com</Header>
	    <Header name="Access-Control-Allow-Credentials" action="add">true</Header>
	  </HTTPResponseChange>
	</xsl:template>

</xsl:stylesheet>