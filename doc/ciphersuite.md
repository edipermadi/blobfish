## Algorithms
Algorithm is defined by the version of the container

| Version | Key Derivation     | Iteration Number | Key Protection                     | Encryption               | Signing         | HMAC       | Hash    | 
|---------|--------------------|------------------|------------------------------------|--------------------------|-----------------|------------|---------|
| 1       | PBKDF2WithHmacSHA1 | 65536            | RSA/ECB/OAEPWithSHA1AndMGF1Padding | AES-128/CBC/PKCS5Padding | SHA256withECDSA | HmacSHA256 | SHA-256 |