# Blobfish Changelog

## v2.4.0-SNAPSHOT

**New Features**

- Find tags similar to given value

## v2.3.0 [October 23, 2017]

**New Features**

- Create blob
- Get blob payload by path
- Get blob metadata (by id or path)
- Update blob path
- Update blob payload
- Delete a blob 

## v2.2.0 [October 22, 2017]

**Enhancement**

- BlobPool::getBlobTags now returns map of `tag-uuid` and `tag-value` 

**New Features**

- List blob by tag
- Create recipient
- List recipient
- Get recipient certificate
- Get recipient metadata
- Update recipient certificate
- Update recipient metadata
- Delete recipient by `recipient-uuid`

## v2.1.0 [October 19, 2017]

**Bugfix**

- Fixed duplicated blob path
- Fixed duplicated recipient certificate

**New Features**

- Create tag
- Remove tag
- Get tag value by `tag-uuid`
- Update tag by `tag-uuid`
- Add tag to blob by `blob-uuid` and `tag-uuid`
- Remove tag from blob by `blob-uuid` and `tag-uuid`

## v2.0.0 [October 17, 2017]

**New Features**

- Create `BlobPool` from existing blobfish container
- List blobs within `BlobPool`
- List tags within `BlobPool`
- List tags associated to a blob

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
