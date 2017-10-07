# BlobPool Database Documentation

H2 Database will be used to store recipient certificates, tags and blobs

## Recipients Table

| Column      | Type                                 | Description                                                  |
|-------------|--------------------------------------|--------------------------------------------------------------|
| id          | INTEGER, PRIMARY KEY, AUTO INCREMENT | Recipient internal identifier                                |
| uuid        | VARCHAR(36), NOT NULL, UNIQUE        | Recipient external identifier (uuid)                         |
| name        | VARCHAR(64), NOT NULL, UNIQUE        | Recipient Name                                               |
| meta        | TEXT, NULL                           | Recipient Metadata                                           |
| certificate | BLOB, NOT NULL                       | DER encoded Recipient Certificate                            |
| imported    | BOOL, NOT NULL                       | True when certificate was imported from a blobfish container |
| created_at  | TIMESTAMP, NOT NULL                  | Entry insertion timestamp                                    |

`recipients` table will be indexed by
- id
- uuid

## Tags Table

| Column      | Type                                 | Description                                                  |
|-------------|--------------------------------------|--------------------------------------------------------------|
| id          | INTEGER, PRIMARY KEY, AUTO INCREMENT | Tag internal identifier                                      |
| uuid        | VARCHAR(36), NOT NULL, UNIQUE        | Tag external identifier                                      |
| tag         | VARHAR(64), NOT NULL, UNIQUE         | Lower case tag name                                          |
| imported    | BOOL, NOT NULL                       | True when tag was imported from a blobfish container         |
| created_at  | TIMESTAMP, NOT NULL                  | Entry insertion timestamp                                    |

`tags` table will be indexed by
- id
- uuid
- tag

## Blobs Table

| Column      | Type                                 | Description                                                  |
|-------------|--------------------------------------|--------------------------------------------------------------|
| id          | INTEGER, PRIMARY KEY, AUTO INCREMENT | Blob internal identifier                                     |
| uuid        | VARCHAR(36), NOT NULL, UNIQUE        | Blob external identifier                                     |
| path        | TEXT, NOT NULL                       | Blob Path                                                    |
| mimetype    | VARCHAR(128), NOT NULL               | Blob mime type                                               |
| payload     | BLOB, NOT NULL                       | Blob payload                                                 |
| imported    | BOOL, NOT NULL                       | True when blob was imported from blobfish container          |
| created_at  | TIMESTAMP, NOT NULL                  | Entry insertion timestamp                                    |

`blobs` table will be indexed by
- id
- uuid
- path

## Blob Tags

| Column      | Type                                 | Description                                                  |
|-------------|--------------------------------------|--------------------------------------------------------------|
| blob_id     | INTEGER, NOT NULL                    | Reference to blob internal identifier                        |
| tag_id      | INTEGER, NOT NULL                    | Reference to tag internal identifier                         |

(blob_id, tag_id) combination has to be unique 