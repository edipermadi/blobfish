package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

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

    @Override
    public void importPayload(final InputStream inputStream, final String password) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException, SQLException {
        /* build decoder */
        final ContainerDecoder decoder = new ContainerDecoderBuilder()
                .setInputStream(inputStream)
                .build();

        /* process blobs */
        final Iterator<Blob> iterator = decoder.getBlobs(password);
        load(iterator);
    }

    @Override
    public void importPayload(InputStream inputStream, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException, SQLException {
        /* build decoder */
        final ContainerDecoder decoder = new ContainerDecoderBuilder()
                .setInputStream(inputStream)
                .build();

        /* process blobs */
        final Iterator<Blob> iterator = decoder.getBlobs(certificate, privateKey);
        load(iterator);
    }

    @Override
    public Map<UUID, String> getTags(final int page, final int size) throws SQLException {
        if (page < 1) {
            throw new IllegalArgumentException("page number is invalid");
        } else if (size < 1) {
            throw new IllegalArgumentException("page size is invalid");
        }

        /* prepare parameters */
        final long offset = (page - 1) * size;
        final String query = queries.getProperty("SQL_SELECT_TAG");

        /* execute query */
        final PreparedStatement preparedStatement = connection.prepareStatement(query);
        preparedStatement.setLong(1, offset);
        preparedStatement.setLong(2, size);
        final ResultSet resultSet = preparedStatement.executeQuery();


        /* read results */
        final Map<UUID, String> tags = new HashMap<>();
        while (resultSet.next()) {
            final String uuid = resultSet.getString("uuid");
            final String tag = resultSet.getString("tag");
            tags.put(UUID.fromString(uuid), tag);

        }

        return tags;
    }

    @Override
    public Map<UUID, Blob.SimplifiedMetadata> getBlobs(int page, int size) throws SQLException {
        if (page < 1) {
            throw new IllegalArgumentException("page number is invalid");
        } else if (size < 1) {
            throw new IllegalArgumentException("page size is invalid");
        }

        /* prepare parameters */
        final long offset = (page - 1) * size;
        final String query = queries.getProperty("SQL_SELECT_BLOB");

        /* execute query */
        final PreparedStatement preparedStatement = connection.prepareStatement(query);
        preparedStatement.setLong(1, offset);
        preparedStatement.setLong(2, size);
        final ResultSet resultSet = preparedStatement.executeQuery();


        /* read results */
        final Map<UUID, Blob.SimplifiedMetadata> blobs = new HashMap<>();
        while (resultSet.next()) {
            final String uuid = resultSet.getString("uuid");
            final String path = resultSet.getString("path");
            final String mimetype = resultSet.getString("mimetype");
            blobs.put(UUID.fromString(uuid), new Blob.SimplifiedMetadata() {
                @Override
                public String getPath() {
                    return path;
                }

                @Override
                public String getMimeType() {
                    return mimetype;
                }
            });

        }

        return blobs;
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

    /**
     * Load blobs into pool
     *
     * @param iterator iterator of blobs
     * @throws SQLException when importing failed
     */
    private void load(final Iterator<Blob> iterator) throws SQLException {
        while (iterator.hasNext()) {
            final Blob blob = iterator.next();
            final byte[] payload = blob.getPayload();
            final Blob.Metadata metadata = blob.getMetadata();
            final Set<String> tags = metadata.getTags();
            final String mimeType = metadata.getMimeType();
            final String path = metadata.getPath();
            final AtomicLong blobId = new AtomicLong(-1);

            /* insert blob */
            final String insertBlobQuery = queries.getProperty("SQL_INSERT_BLOB");
            try (final PreparedStatement preparedStatement = connection.prepareStatement(insertBlobQuery, Statement.RETURN_GENERATED_KEYS)) {
                preparedStatement.setString(1, path);
                preparedStatement.setString(2, mimeType);
                preparedStatement.setBinaryStream(3, new ByteArrayInputStream(payload));
                preparedStatement.setBoolean(4, true);
                if (preparedStatement.executeUpdate() == 0) {
                    throw new SQLException("failed to insert blob");
                }

                /* get blob id */
                final ResultSet resultSet = preparedStatement.getGeneratedKeys();
                if (!resultSet.next()) {
                    throw new SQLException("failed to get inserted blob id");
                }
                blobId.set(resultSet.getLong(1));
            }

            /* insert tags */
            final String mergeTagQuery = queries.getProperty("SQL_MERGE_TAG");
            final String insertBlobTagQuery = queries.getProperty("SQL_INSERT_BLOB_TAG");
            for (final String tag : tags) {
                try (final PreparedStatement preparedStatement = connection.prepareStatement(mergeTagQuery)) {
                    preparedStatement.setString(1, tag);
                    if (preparedStatement.executeUpdate() == 0) {
                        throw new SQLException("failed to merge tag");
                    }
                }

                /* insert tags association */
                try (final PreparedStatement preparedStatement = connection.prepareStatement(insertBlobTagQuery)) {
                    preparedStatement.setLong(1, blobId.get());
                    preparedStatement.setString(2, tag);
                    if (preparedStatement.executeUpdate() == 0) {
                        throw new SQLException("failed to insert blob-tag association");
                    }
                }
            }
        }
    }
}
