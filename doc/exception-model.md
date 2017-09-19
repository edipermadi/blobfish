## Blobfish Exception Model

Here is the exception model of Blobfish

```
BlobfishException
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