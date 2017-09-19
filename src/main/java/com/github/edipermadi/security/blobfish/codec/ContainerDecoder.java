package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.*;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
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
     * @throws PasswordNotSupportedException when password is not supported
     * @throws IncorrectPasswordException    when password is incorrect
     */
    Blob getBlob(int blobId, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob entry
     *
     * @param index         blob id from 0 to (blobCount - 1)
     * @param decryptionKey RSA private key to decrypt blob
     * @return
     * @throws InvalidDecryptionKeyException   when other than RSA private key is used
     * @throws IncorrectDecryptionKeyException when decryption private key is incorrect
     */
    Blob getBlob(int index, PrivateKey decryptionKey) throws BlobfishDecodeException;
}
