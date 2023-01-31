# Solver testdata directory

In order to run the tests, create a file config.json in this directory.

## Reference

```json
{
  "username": "your username",
  "password": "your password",

  "ip": "IP to fix this session to (optional)",
  
  "apiUrl": "https://api.url/base-path (optional)",
  
  "ttl": "TTL for added records (optional)"
}
```

Note that if you try to use the Openprovider sandbox API (at api.sandbox.openprovider.nl), then the tests will fail 
because no actual zone updates will be published, on account of there not being any "sandbox" DNS server.
