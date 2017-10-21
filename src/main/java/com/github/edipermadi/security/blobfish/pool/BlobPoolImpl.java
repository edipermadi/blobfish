package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoder;
import com.github.edipermadi.security.blobfish.codec.ContainerDecoderBuilder;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
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
    public Map<UUID, String> listAvailableTags(final int page, final int size) throws SQLException {
        if (page < 1) {
            throw new IllegalArgumentException("page number is invalid");
        } else if (size < 1) {
            throw new IllegalArgumentException("page size is invalid");
        }

        /* prepare parameters */
        final long offset = (page - 1) * size;
        final String query = queries.getProperty("SQL_SELECT_TAGS");

        /* execute query */
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
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
    }

    @Override
    public Map<UUID, Blob.SimplifiedMetadata> listAvailableBlobs(int page, int size) throws SQLException {
        if (page < 1) {
            throw new IllegalArgumentException("page number is invalid");
        } else if (size < 1) {
            throw new IllegalArgumentException("page size is invalid");
        }

        /* prepare parameters */
        final long offset = (page - 1) * size;
        final String query = queries.getProperty("SQL_LIST_BLOB");

        /* execute query */
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
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
    }

    @Override
    public Map<UUID, Blob.SimplifiedMetadata> listBlobsWithTag(final UUID tagId, final int page, final int size) throws SQLException {
        if (tagId == null) {
            throw new IllegalArgumentException("invalid tag identifier");
        } else if (page < 1) {
            throw new IllegalArgumentException("page number is invalid");
        } else if (size < 1) {
            throw new IllegalArgumentException("page size is invalid");
        }

        /* prepare parameters */
        final long offset = (page - 1) * size;
        final String query = queries.getProperty("SQL_LIST_BLOB_WITH_TAG_UUID");

        /* execute query */
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, tagId.toString());
            preparedStatement.setLong(2, offset);
            preparedStatement.setLong(3, size);
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
    }

    @Override
    public Map<UUID, String> getBlobTags(final UUID blobId) throws SQLException {
        if (blobId == null) {
            throw new IllegalArgumentException("blobId is null");
        }

        /* execute query */
        final String query = queries.getProperty("SQL_SELECT_BLOBS_TAGS_BY_BLOB_UUID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, blobId.toString());
            final ResultSet resultSet = preparedStatement.executeQuery();

            final Map<UUID, String> tags = new HashMap<>();
            while (resultSet.next()) {
                final String uuid = resultSet.getString("uuid");
                final String tag = resultSet.getString("tag");
                tags.put(UUID.fromString(uuid), tag);
            }

            return tags;
        }
    }

    @Override
    public String getTag(final UUID tagId) throws SQLException {
        if (tagId == null) {
            throw new IllegalArgumentException("tagId is null");
        }

        /* execute query */
        final String query = queries.getProperty("SQL_SELECT_TAGS_VALUE_BY_TAG_ID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, tagId.toString());
            final ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new NoSuchElementException("no such tag with uuid " + tagId);
            }

            return resultSet.getString("tag");
        }
    }

    @Override
    public boolean updateTag(final UUID tagId, final String tag) throws SQLException {
        if (tagId == null) {
            throw new IllegalArgumentException("tagId is null");
        } else if (tag.trim().isEmpty()) {
            throw new IllegalArgumentException("tag is invalid");
        }

        /* make it lowercase */
        final String value = tag.toLowerCase();

        /* check if new value is exist */
        final String countTagByValueQuery = queries.getProperty("SQL_COUNT_TAG_BY_VALUE");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(countTagByValueQuery)) {
            preparedStatement.setString(1, value);
            final ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new IllegalStateException(String.format("failed to check existence of tag '%s'", tag));
            }

            if (resultSet.getLong("count") > 0) {
                return false;
            }
        }

        /* execute query */
        final String query = queries.getProperty("SQL_UPDATE_TAG_VALUE_BY_TAG_ID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, value);
            preparedStatement.setString(2, tagId.toString());
            return preparedStatement.executeUpdate() > 0;
        }
    }

    @Override
    public boolean removeTag(final UUID tagId) throws SQLException {
        if (tagId == null) {
            throw new IllegalArgumentException("tagId is null");
        }

        /* remove any association to this tag */
        final String removeBlobsTagsByTagIdQuery = queries.getProperty("SQL_REMOVE_BLOBS_TAGS_BY_TAG_ID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(removeBlobsTagsByTagIdQuery)) {
            preparedStatement.setString(1, tagId.toString());
            preparedStatement.executeUpdate();
        }

        /* remove tag by id */
        final String removeTagsByTagIdQuery = queries.getProperty("SQL_DELETE_TAGS_BY_TAG_ID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(removeTagsByTagIdQuery)) {
            preparedStatement.setString(1, tagId.toString());
            return preparedStatement.executeUpdate() > 0;
        }
    }

    @Override
    public UUID createTag(final String tag) throws SQLException {
        if ((tag == null) || tag.trim().isEmpty()) {
            throw new IllegalArgumentException("invalid tag");
        }

        final String value = tag.toLowerCase();
        final String queryMerge = queries.getProperty("SQL_MERGE_TAGS_BY_TAG_VALUE");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(queryMerge)) {
            preparedStatement.setString(1, value);
            if (preparedStatement.executeUpdate() == 0) {
                throw new SQLException("failed to create tag");
            }
        }

        final String queryGet = queries.getProperty("SQL_SELECT_TAGS_UUID_BY_TAG_VALUE");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(queryGet)) {
            preparedStatement.setString(1, value);
            final ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new IllegalStateException("failed to get created tag");
            }

            final String uuidStr = resultSet.getString("uuid");
            return UUID.fromString(uuidStr);
        }
    }

    @Override
    public boolean addTagToBlob(final UUID blobId, final UUID tagId) throws SQLException {
        if (blobId == null) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (tagId == null) {
            throw new IllegalArgumentException("invalid tag identifier");
        }

        final String query = queries.getProperty("SQL_INSERT_BLOBS_TAGS_BY_BLOB_ID_AND_TAG_ID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, blobId.toString());
            preparedStatement.setString(2, tagId.toString());
            return preparedStatement.executeUpdate() > 0;
        }
    }

    @Override
    public boolean removeTagFromBlob(final UUID blobId, final UUID tagId) throws SQLException {
        if (blobId == null) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (tagId == null) {
            throw new IllegalArgumentException("invalid tag identifier");
        }

        final String query = queries.getProperty("SQL_REMOVE_BLOBS_TAGS_BY_BLOB_ID_AND_TAG_ID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, blobId.toString());
            preparedStatement.setString(2, tagId.toString());
            return preparedStatement.executeUpdate() > 0;
        }
    }

    @Override
    public byte[] getBlobPayload(UUID blobId) throws SQLException, IOException {
        if (blobId == null) {
            throw new IllegalArgumentException("blobId is null");
        }

        /* execute query */
        final String query = queries.getProperty("SQL_GET_BLOB_BY_UUID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, blobId.toString());
            final ResultSet resultSet = preparedStatement.executeQuery();

            if (!resultSet.next()) {
                throw new NoSuchElementException("no such blob " + blobId);
            }
            final InputStream inputStream = resultSet.getBinaryStream("payload");
            return IOUtils.toByteArray(inputStream);
        }
    }

    @Override
    public boolean createRecipient(final String name, final String metadata, final X509Certificate certificate) throws SQLException, CertificateEncodingException {
        if ((name == null) || name.trim().isEmpty()) {
            throw new IllegalArgumentException("recipient name is null/empty");
        } else if (certificate == null) {
            throw new IllegalArgumentException("certificate is null");
        }

        final String query = queries.getProperty("SQL_INSERT_INTO_RECIPIENTS");
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(certificate.getEncoded());
             final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, name);
            preparedStatement.setString(2, metadata);
            preparedStatement.setBinaryStream(3, bais);
            return preparedStatement.executeUpdate() > 0;
        } catch (final IOException ex) {
            throw new CertificateEncodingException(ex);
        }
    }

    @Override
    public Map<UUID, String> listRecipient(final int page, final int size) throws SQLException {
        if (page < 1) {
            throw new IllegalArgumentException("page number is invalid");
        } else if (size < 1) {
            throw new IllegalArgumentException("page size is invalid");
        }

        /* prepare parameters */
        final long offset = (page - 1) * size;

        /* run query */
        final Map<UUID, String> recipients = new HashMap<>();
        final String query = queries.getProperty("SQL_SELECT_RECIPIENTS");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setLong(1, offset);
            preparedStatement.setLong(2, page);
            final ResultSet resultSet = preparedStatement.executeQuery();
            while (resultSet.next()) {
                final String uuid = resultSet.getString("uuid");
                final String name = resultSet.getString("name");
                recipients.put(UUID.fromString(uuid), name);
            }
            return recipients;
        }
    }

    @Override
    public X509Certificate getRecipientCertificate(final UUID recipientId) throws SQLException, CertificateException {
        if (recipientId == null) {
            throw new IllegalArgumentException("recipientId is null");
        }

        /* run query */
        final String query = queries.getProperty("SQL_SELECT_RECIPIENTS_CERTIFICATE_BY_UUID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, recipientId.toString());
            final ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new NoSuchElementException("no such recipient " + recipientId);
            }

            /* parse certificate */
            try (final InputStream inputStream = resultSet.getBinaryStream("certificate")) {
                final CertificateFactory factory = CertificateFactory.getInstance("X.509");
                return (X509Certificate) factory.generateCertificate(inputStream);
            } catch (final IOException ex) {
                throw new CertificateException(ex);
            }
        }
    }

    @Override
    public String getRecipientMetadata(final UUID recipientId) throws SQLException {
        if (recipientId == null) {
            throw new IllegalArgumentException("recipientId is null");
        }

        /* run query */
        final String query = queries.getProperty("SQL_SELECT_RECIPIENTS_METADATA_BY_UUID");
        try (final PreparedStatement preparedStatement = connection.prepareStatement(query)) {
            preparedStatement.setString(1, recipientId.toString());
            final ResultSet resultSet = preparedStatement.executeQuery();
            if (!resultSet.next()) {
                throw new NoSuchElementException("no such recipient " + recipientId);
            }

            return resultSet.getString("metadata");
        }
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
            final String mergeTagQuery = queries.getProperty("SQL_MERGE_TAGS_BY_TAG_VALUE");
            final String insertBlobTagQuery = queries.getProperty("SQL_INSERT_BLOBS_TAGS_BY_BLOB_ID_AND_TAG_VALUE");
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
