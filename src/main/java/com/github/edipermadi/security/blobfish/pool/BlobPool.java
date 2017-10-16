package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.util.List;
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
     * Get tags
     *
     * @param page number starts from 1
     * @param size page size at least 1
     * @return map of tag id and string
     * @throws SQLException when reading tags failed
     */
    Map<UUID, String> getTags(int page, int size) throws SQLException;
}
