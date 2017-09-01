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

| Version | Key Derivation | Key Protection                        | Encryption               | Signing         | HMAC       | Hash   | 
|---------|----------------|---------------------------------------|--------------------------|-----------------|------------|--------|
| 1       | PBKDF2         | RSA/None/OAEPWithSHA256AndMGF1Padding | AES-128/CBC/PKCS5Padding | SHA256withECDSA | HmacSHA256 | SHA256 | 