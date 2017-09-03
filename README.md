# blobfish

## Overview
An ugly blob container based on protobuf

## Features
- Versioned container
- Multiple blob container
- Blob mimetype indicator
- Blob HMAC and signature
- Blob encryption
- Blob Tagging
- Blob location path (simulates storage tree view)
- Public key based symmetric-key protection for recipient
- Optional PBKDF2 based key protection

## Algorithms
Algorithm is defined by the version of the container

| Version | Key Derivation     | Iteration Number | Key Protection                        | Encryption               | Signing         | HMAC       | Hash   | 
|---------|--------------------|------------------|---------------------------------------|--------------------------|-----------------|------------|--------|
| 1       | PBKDF2WithHmacSHA1 | 65536            | RSA/None/OAEPWithSHA256AndMGF1Padding | AES-128/CBC/PKCS5Padding | SHA256withECDSA | HmacSHA256 | SHA256 |

## Container Information
- container magic code identifier is 0x75676c7966697368 -> 'uglyfish'
- container extension is ".ugly" 