# Backend signer

Web API that returns an ECDSA signature of a given address + random nonce.

### Example run
Run server
```bash
make run
```
Call API
```bash
curl http://localhost:8080/sign/<address>
```
