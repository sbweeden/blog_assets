# python3 version of PAC decoder

## Pre-requisites

```
pip3 install future
pip3 install asn1
```

## Testing the code

There is a script included `testCredParser.sh` which you should look at - it includes three examples of calling the credential parser:
 - with bad input
 - with an unauthenticated credential
 - with an authenticated credential for `testuser` that is also populated with groups

 ## Other details

 The main functional entry point is the `decodePACHeader` function in `credParser.py`

 