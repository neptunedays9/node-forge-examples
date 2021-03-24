# node-forge-examples

## extract pem public certificate from cert file

```openssl x509 -n certfile.cert -inform der -text```


## convert the file to single string

```awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' cert-name.pem```

## extract x509 from pfx
```openssl pkcs12 -in filename.pfx -passin pass:<password> -nokeys | openssl x509 -noout -enddate```

## base64
```echo username:password | openssl base64```
```echo encodedtext | base64 --decode```

