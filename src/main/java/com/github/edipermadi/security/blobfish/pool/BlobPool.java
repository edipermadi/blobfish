package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.Map;
import java.util.Set;
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
     * List available tags
     *
     * @param page number starts from 1
     * @param size page size at least 1
     * @return map of tag id and string
     * @throws SQLException when reading tags failed
     */
    Map<UUID, String> listAvailableTags(int page, int size) throws SQLException;

    /**
     * List available blobs
     *
     * @param page number starts from 1
     * @param size page size at least 1
     * @return map of blob uuid and corresponding metadata
     * @throws SQLException when reading blob failed
     */
    Map<UUID, Blob.SimplifiedMetadata> listAvailableBlobs(int page, int size) throws SQLException;

    /**
     * Get tags of a particular blob
     *
     * @param blobId blob identifier
     * @return map of tag-uuid and its value
     * @throws SQLException when reading tags failed
     */
    Map<UUID,String> getBlobTags(UUID blobId) throws SQLException;

    /**
     * Create a new tag
     *
     * @param tag new tag to be created
     * @return UUID of new or existing tag
     * @throws SQLException when inserting tag failed
     */
    UUID createTag(String tag) throws SQLException;

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
     * @param tagId tag identifier
     * @return true when tag deleted successfully
     * @throws SQLException when updating tag failed
     */
    boolean removeTag(UUID tagId) throws SQLException;

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
     * Get blob payload
     *
     * @param blobId blob identifier
     * @return byte array of blob
     * @throws SQLException when reading payload failed
     * @throws IOException  when reading blob payload failed
     */
    byte[] getBlobPayload(UUID blobId) throws SQLException, IOException;
}
