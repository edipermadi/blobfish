package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Map;
import java.util.UUID;

/**
 * Blob Pool interface
 *
 * @author Edi Permadi
 */
public interface BlobPool {
    /**
     * Import blobfish container into pool with password
     *
     * @param inputStream input stream of blobfish container
     * @param password    recipient decryption password
     * @throws BlobfishDecodeException when decoding failed
     * @throws BlobfishCryptoException when crypto operation failed
     * @throws IOException             when input stream accessing failed
     * @throws CertificateException    when sender certificate recovery failed
     * @throws SQLException            when importing blob to pool failed
     */
    void importPayload(InputStream inputStream, final String password) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException, SQLException;

    /**
     * Import blobfish container into pool with certificate and private key
     *
     * @param inputStream input stream of blobfish container
     * @param certificate recipient decryption certificate
     * @param privateKey  recipient encryption private key
     * @throws BlobfishDecodeException when decoding failed
     * @throws BlobfishCryptoException when crypto operation failed
     * @throws IOException             when input stream accessing failed
     * @throws CertificateException    when sender certificate recovery failed
     * @throws SQLException            when importing blob to pool failed
     */
    void importPayload(InputStream inputStream, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException, SQLException;

    /**
     * Create a new tag
     *
     * @param tag new tag to be created
     * @return UUID of new or existing tag
     * @throws SQLException when inserting tag failed
     */
    UUID createTag(String tag) throws SQLException;

    /**
     * List tags
     *
     * @param page number starts from 1
     * @param size page size at least 1
     * @return map of tag id and string
     * @throws SQLException when reading tags failed
     */
    Map<UUID, String> listTags(int page, int size) throws SQLException;

    /**
     * Get tag value by tag uuid
     *
     * @param tagId tag identifier
     * @return tag value
     * @throws SQLException when fetching tag value failed
     */
    String getTag(UUID tagId) throws SQLException;

    /**
     * Remove a tag
     *
     * @param tagId tag identifier
     * @param tag   new value of tag
     * @return true when updated successfully
     * @throws SQLException when updating tag failed
     */
    boolean updateTag(UUID tagId, String tag) throws SQLException;

    /**
     * Remove a tag
     *
     * @param tagId tag identifier
     * @return true when tag deleted successfully
     * @throws SQLException when updating tag failed
     */
    boolean removeTag(UUID tagId) throws SQLException;

    /**
     * Create blob
     *
     * @param path     blob path
     * @param mimetype blob mimetype
     * @param payload  blob payload
     * @return UUID of created blob
     * @throws SQLException when inserting new blob failed
     */
    UUID createBlob(String path, String mimetype, InputStream payload) throws SQLException;

    /**
     * List blobs
     *
     * @param page number starts from 1
     * @param size page size at least 1
     * @return map of blob uuid and corresponding metadata
     * @throws SQLException when reading blob failed
     */
    Map<UUID, Blob.SimplifiedMetadata> listBlobs(int page, int size) throws SQLException;

    /**
     * List blobs which has given tag
     *
     * @param tagId tag identifier
     * @param page  number starts from 1
     * @param size  page size at least 1
     * @return map of blob uuid and corresponding metadata
     * @throws SQLException when reading blob failed
     */
    Map<UUID, Blob.SimplifiedMetadata> listBlobsWithTag(UUID tagId, int page, int size) throws SQLException;

    /**
     * Add tag to a blob
     *
     * @param blobId blob identifier
     * @param tagId  tag identifier
     * @return true when added successfully
     * @throws SQLException when assigning tag failed
     */
    boolean addTagToBlob(UUID blobId, UUID tagId) throws SQLException;

    /**
     * Remove tag from a blob
     *
     * @param blobId blob identifier
     * @param tagId  tag identifier
     * @return true when removed successfully
     * @throws SQLException when de-assigning tag failed
     */
    boolean removeTagFromBlob(UUID blobId, UUID tagId) throws SQLException;

    /**
     * Get tags of a particular blob
     *
     * @param blobId blob identifier
     * @return map of tag-uuid and its value
     * @throws SQLException when reading tags failed
     */
    Map<UUID, String> getBlobTags(UUID blobId) throws SQLException;

    /**
     * Get blob payload by blob-uuid
     *
     * @param blobId blob identifier
     * @return byte array of blob
     * @throws SQLException when reading payload failed
     * @throws IOException  when reading blob payload failed
     */
    byte[] getBlobPayload(UUID blobId) throws SQLException, IOException;

    /**
     * Get blob payload by blob-path
     *
     * @param path blob path
     * @return byte array of blob
     * @throws SQLException when reading payload failed
     * @throws IOException  when reading blob payload failed
     */
    byte[] getBlobPayload(String path) throws SQLException, IOException;

    /**
     * Add recipient
     *
     * @param name        name of recipient
     * @param metadata    optional metadata for user
     * @param certificate encryption certificate, must be RSA
     * @return UUID of recipient
     * @throws SQLException                 when recipient creation failed
     * @throws CertificateEncodingException when encoding certificate failed
     */
    UUID createRecipient(String name, String metadata, X509Certificate certificate) throws SQLException, CertificateEncodingException;

    /**
     * List recipient
     *
     * @param page page number, starts from 1
     * @param size page size, at least 1
     * @return map of recipient-uuid to recipient-name
     * @throws SQLException when listing recipient failed
     */
    Map<UUID, String> listRecipient(int page, int size) throws SQLException;

    /**
     * Get recipient certificate
     *
     * @param recipientId recipient identifier
     * @return RSA X.509 certificate of recipient
     * @throws SQLException         when retrieving recipient failed
     * @throws CertificateException when parsing certificate failed
     */
    X509Certificate getRecipientCertificate(UUID recipientId) throws SQLException, CertificateException;

    /**
     * Get recipient metadata
     *
     * @param recipientId recipient identifier
     * @return recipient string or null if not set
     * @throws SQLException when retrieving recipient failed
     */
    String getRecipientMetadata(UUID recipientId) throws SQLException;

    /**
     * Update recipient certificate
     *
     * @param recipientId recipient identifier
     * @param certificate new recipient certificate
     * @return true when updated successfully
     * @throws SQLException         when updating failed
     * @throws CertificateException when encoding certificate failed
     */
    boolean updateRecipientCertificate(UUID recipientId, X509Certificate certificate) throws SQLException, CertificateException;

    /**
     * Update recipient metadata
     *
     * @param recipientId recipient identifier
     * @param metadata    new recipient metadata
     * @return true when updated successfully
     * @throws SQLException when updating failed
     */
    boolean updateRecipientMetadata(UUID recipientId, String metadata) throws SQLException;

    /**
     * Delete recipient
     *
     * @param recipientId recipient identifier
     * @return true when deleted successfully
     * @throws SQLException when deletion failed
     */
    boolean deleteRecipient(UUID recipientId) throws SQLException;
}
