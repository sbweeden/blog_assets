# imports
import fileinput
import json
from credParser import decodePACHeader

#################################################################
# Main function starts here - reads iv-creds header from stdin
#################################################################
for line in fileinput.input():
    credJSON = decodePACHeader(line.rstrip())
    print("credJSON: " + json.dumps(credJSON))