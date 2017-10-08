package com.github.edipermadi.security.blobfish.pool;

import java.io.File;
import java.io.IOException;
import java.sql.SQLException;

/**
 * Blob Pool Builder
 *
 * @author Edi Permadi
 */
public final class BlobPoolBuilder {
    private File dbFile;
    private String dbPassword;

    /**
     * Set db as file
     *
     * @param dbFile database file
     * @return this instance
     */
    public BlobPoolBuilder setDbFile(final File dbFile) {
        if (dbFile == null) {
            throw new IllegalArgumentException("dn file is null");
        }
        this.dbFile = dbFile;
        return this;
    }

    /**
     * Set database password
     *
     * @param dbPassword database password
     * @return this instance
     */
    public BlobPoolBuilder setDbPassword(final String dbPassword) {
        if (dbPassword == null) {
            throw new IllegalArgumentException("db password is null");
        }
        this.dbPassword = dbPassword;
        return this;
    }

    public BlobPool build() throws SQLException, ClassNotFoundException, IOException {
        return new BlobPoolImpl(dbFile, dbPassword);
    }
}
