<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
	version="1.0" xmlns:external="http://xsltfunctions.isam.ibm.com">

 <!--
 	Used to remove the x-frame-options response header, and insert a content-security-policy
 	to permit cross-origin embedding
 	
 	Configure as a response http transformation with something like:
 	
 	[http-transformations]
 	iframe-headers = iframe-headers.xsl
 	
 	[http-transformations:iframe-headers]
 	request-match = response:GET /mga/sps/authsvc/policy/amiauthenticated*

  -->

	<!-- Firstly, strip any space elements -->
	<xsl:strip-space elements="*" />


	<!--
	  Perform a match on the root of the document. Output the required
	  HTTPResponseChange elements.
	-->
	<xsl:template match="/">
	  <HTTPResponseChange>
	    <Header name="x-frame-options" action="remove">SAMEORIGIN</Header>
	    <Header name="Content-Security-Policy" action="add">frame-ancestors https://idp.com;</Header>
	  </HTTPResponseChange>
	</xsl:template>

</xsl:stylesheet>