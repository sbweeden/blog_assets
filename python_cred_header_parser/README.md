# python3 version of PAC decoder

## Pre-requisites

```
pip3 install future
pip3 install asn1
```

## Details

The main functional entry point is the `decodePACHeader` function in `credParser.py`

There is a script included `testCredParser.sh` which you should look at - it includes three examples of calling the credential parser test app:
 - with bad input
 - with an unauthenticated credential
 - with an authenticated credential for `testuser` that is also populated with groups

