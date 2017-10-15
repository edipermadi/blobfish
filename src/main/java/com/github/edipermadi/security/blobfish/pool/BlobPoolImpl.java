package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Properties;

/**
 * Blob Pool Implementation
 *
 * @author Edi Permadi
 */
final class BlobPoolImpl implements BlobPool {
    private final Properties queries;
    private final Connection connection;

    /**
     * Class constructor
     *
     * @param dbFile     database file
     * @param dbPassword database password
     * @throws SQLException           when connection to db cannot be established
     * @throws ClassNotFoundException when h2 driver not found
     * @throws IOException            when loading queries template failed
     */
    BlobPoolImpl(final File dbFile, final String dbPassword) throws SQLException, ClassNotFoundException, IOException {
        if (dbFile == null) {
            throw new IllegalArgumentException("db file is null");
        } else if ((dbPassword == null) || (dbPassword.isEmpty())) {
            throw new IllegalArgumentException("db password is null/empty");
        }

        final String url = String.format("jdbc:h2:file:%s;CIPHER=AES", dbFile.getAbsolutePath());
        final String passwords = String.format("password %s", dbPassword);

        queries = loadQueries();
        connection = getDbConnection(url, passwords);
        createTables();
    }

    /**
     * Create tables
     *
     * @throws SQLException when table creation failed
     */
    private void createTables() throws SQLException {
        try (final Statement stmt = connection.createStatement()) {
            /* create tables */
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_TABLE_RECIPIENTS"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_TABLE_TAGS"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_TABLE_BLOBS"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_TABLE_BLOBS_TAGS"));

            /* create indexes */
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_RECIPIENTS_UUID"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_RECIPIENTS_NAME"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_TAGS_UUID"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_TAGS_TAG"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_BLOBS_UUID"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_BLOBS_PATH"));
            stmt.executeUpdate(queries.getProperty("SQL_CREATE_INDEX_BLOBS_TAGS_UNIQUE"));
        }
        connection.commit();
    }

    /**
     * Load queries from properties file
     *
     * @return properties file
     * @throws IOException when loading failed
     */
    private Properties loadQueries() throws IOException {
        try (final InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sql.properties");
             final InputStreamReader reader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            final Properties properties = new Properties();
            properties.load(reader);
            return properties;
        }
    }

    /**
     * Get database connection
     *
     * @param url       url of database
     * @param passwords user and database password
     * @return database conection object
     * @throws ClassNotFoundException when H2 driver was not found
     * @throws SQLException           when establishing connection failed
     */
    private Connection getDbConnection(final String url, final String passwords) throws ClassNotFoundException, SQLException {
        Class.forName("org.h2.Driver");
        return DriverManager.getConnection(url, "sa", passwords);
    }

    @Override
    public void load(final InputStream inputStream, final String password) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException {
        if (inputStream == null) {
            throw new IllegalArgumentException("input stream is null");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        }

        /* build decoder */
        final ContainerDecoder decoder = new ContainerDecoderBuilder()
                .setInputStream(inputStream)
                .build();

        /* process blobs */
        decoder.getBlobs(password);
    }

    @Override
    public void load(InputStream inputStream, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (inputStream == null) {
            throw new IllegalArgumentException("input stream is null");
        }
    }
}
