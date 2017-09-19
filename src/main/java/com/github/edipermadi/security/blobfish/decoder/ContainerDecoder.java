package com.github.edipermadi.security.blobfish.decoder;

import com.github.edipermadi.security.blobfish.Blob;

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
     * @return blob signing certificate
     */
    X509Certificate getSigningCertificate();

    /**
     * Get container creation date
     * @return container creation date
     */
    Date getCreationDate();

    /**
     * Get blob entry
     * @param blobId blob id from 0 to (blobCount - 1)
     * @param password password to open
     * @return
     */
    Blob getBlob(int blobId, String password);

    Blob getBlob(int index, PrivateKey decryptionKey);
}
