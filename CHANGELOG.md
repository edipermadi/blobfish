# Blobfish Changelog

## v2.0.0 [October 17, 2017]

**New Features**

- Create `BlobPool` from existing blobfish container
- List blobs within `BlobPool`
- List tags within `BlobPool`
- List associated to a blob

## v1.1.0 [October 4, 2017]

**New Features**

- Generate javadoc-jar while building package
- Generate source-jar while building package
- Added error_prone checking
- Tags forced to lowercase during encoding
- List available tags
- List directory
- Get blob by id/path
- Get blob metadata by id/path
- Get blob payload by id/path
- List blob by tags

## v1.0.0 [October 1, 2017]

**Features:**
- Multiple blob support
- PBKDF2WithHmacSHA1 based key from password derivation
- AES/CBC/PKCS5Padding blob protection
- RSA/ECB/OAEPWithSHA1AndMGF1Padding symmetric key protection
- SHA256withECDSA blob authentication
- HmacSHA256 blob integration checking
- Multiple recipient based key protection
- Blob mimetype hint
- Blob tagging
- Blob path to simulate directory view
