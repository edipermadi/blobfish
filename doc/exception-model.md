## Blobfish Exception Model

Here is the exception model of Blobfish

```
BlobfishException
|
`--BlobfishCryptoException
|  |
|  `--CertificateHashingException
|  |
|  `--CertificateSerializationException
|  |
|  `--CipherSetupException
|  |
|  `--KeyDerivationException
|  |
|  `--MacSetupException
|  |
|  `--SignerSetupException
|
`--BlobfishEncodeException
|  |
|  `--KeyProtectionException
|  |
|  `--SignCalculationException
|
`--BlobfishDecodeException
   |
   `--BlobNotFoundException
   |
   `--KeyUnprotectionException
   |
   `--IncorrectDecryptionKeyException
   |
   `--IncorrectPasswordException
   |
   `--InvalidDecryptionKeyException
   |
   `--NotAuthenticatedException
   |
   `--PasswordNotSupportedException
   |
   `--SignVerificationException
```