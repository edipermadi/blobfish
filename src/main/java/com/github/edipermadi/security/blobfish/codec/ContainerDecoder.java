package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Blobfish container decoder interface
 *
 * @author Edi Permadi
 */
public interface ContainerDecoder {
    /**
     * Return count of blob stored in this container
     *
     * @return count of blob
     */
    int getBlobCount();

    /**
     * Get blob signing certificate
     *
     * @return blob signing certificate
     */
    X509Certificate getSigningCertificate();

    /**
     * Get container creation date
     *
     * @return container creation date
     */
    Date getCreationDate();

    /**
     * Get blob entry
     *
     * @param blobId   blob id from 0 to (blobCount - 1)
     * @param password password to open
     * @return decrypted blob entry, see {@link Blob}
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob getBlob(int blobId, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob entry
     *
     * @param index       blob id from 0 to (blobCount - 1)
     * @param privateKey  RSA private key to unprotect blob symmetric-key
     * @param certificate key-protection certificate
     * @return blob object
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob getBlob(int index, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException;
}
