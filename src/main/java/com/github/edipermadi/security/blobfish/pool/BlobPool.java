package com.github.edipermadi.security.blobfish.pool;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.SQLException;

/**
 * Blob Pool interface
 *
 * @author Edi Permadi
 */
public interface BlobPool {
    /**
     * Load blobfish container into pool with password
     *
     * @param inputStream input stream of blobfish container
     * @param password    recipient decryption password
     * @throws BlobfishDecodeException when decoding failed
     * @throws BlobfishCryptoException when crypto operation failed
     * @throws IOException             when input stream accessing failed
     * @throws CertificateException    when sender certificate recovery failed
     * @throws SQLException            when importing blob to pool failed
     */
    void load(InputStream inputStream, final String password) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException, SQLException;

    /**
     * Load blobfish container into pool with certificate and private key
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
    void load(InputStream inputStream, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException, IOException, CertificateException, SQLException;
}
