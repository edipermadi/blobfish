# BlobPool Database Documentation

H2 Database will be used to store recipient certificates, tags and blobs

## Recipient Table

| Column      | Type                                 | Description                          |
|-------------|--------------------------------------|--------------------------------------|
| id          | INTEGER, PRIMARY KEY, AUTO INCREMENT | Recipient internal identifier        |
| uuid        | VARCHAR(36), NOT NULL, UNIQUE        | Recipient external identifier (uuid) |
| name        | VARCHAR(64), NOT NULL, UNIQUE        | Recipient Name                       |
| meta        | TEXT, NULL                           | Recipient Metadata                   |
| certificate | BLOB                                 | DER encoded Recipient Certificate    |
 