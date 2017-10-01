## Blobfish Exception Model

Here is the exception model of Blobfish

```
BlobfishException
|
`--BlobfishCryptoException
|  |
|  `--MacSetupException
|  |
|  `--SignerSetupException
|
`--BlobfishEncodeException
|
`--BlobfishDecodeException
   |
   `--PasswordNotSupportedException
   |
   `--IncorrectPasswordException
   |
   `--InvalidDecryptionKeyException
   |
   `--IncorrectDecryptionKeyException
```