## Blobfish Exception Model

Here is the exception model of Blobfish

```
BlobfishException
|
`--BlobfishCryptoException
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