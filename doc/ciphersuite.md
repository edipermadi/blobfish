## Algorithms
Algorithm is defined by the version of the container

| Version | Compression | Key Derivation     | Iteration Number | Key Protection                     | Encryption               | Signing         | HMAC       | Hash    | 
|---------|-------------|--------------------|------------------|------------------------------------|--------------------------|-----------------|------------|---------|
| 1       | None        | PBKDF2WithHmacSHA1 | 65536            | RSA/ECB/OAEPWithSHA1AndMGF1Padding | AES-128/CBC/PKCS5Padding | SHA256withECDSA | HmacSHA256 | SHA-256 |
| 2       | Gzip        | PBKDF2WithHmacSHA1 | 65536            | RSA/ECB/OAEPWithSHA1AndMGF1Padding | AES-128/CBC/PKCS5Padding | SHA256withECDSA | HmacSHA256 | SHA-256 |