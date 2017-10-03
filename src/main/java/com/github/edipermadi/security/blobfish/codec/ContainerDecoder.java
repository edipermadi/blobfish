package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Set;

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
     * Get blob metadata by password and blobId
     *
     * @param blobId   blob id from 0 to (blobCount - 1)
     * @param password password to open
     * @return blob metadata object
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob.Metadata getMetadata(int blobId, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob metadata by password and path
     *
     * @param path     blob path
     * @param password password to open
     * @return blob metadata object
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob.Metadata getMetadata(String path, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob metadata by privateKey and blobId
     *
     * @param blobId      blob id from 0 to (blobCount - 1)
     * @param privateKey  RSA private key to unprotect blob symmetric-key
     * @param certificate key-protection certificate
     * @return blob metadata object
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob.Metadata getMetadata(int blobId, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob metadata by privateKey and path
     *
     * @param path        blob path
     * @param privateKey  RSA private key to unprotect blob symmetric-key
     * @param certificate key-protection certificate
     * @return blob metadata object
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob.Metadata getMetadata(String path, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob entry by password and blobId
     *
     * @param blobId   blob id from 0 to (blobCount - 1)
     * @param password password to open
     * @return decrypted blob entry, see {@link Blob}
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob getBlob(int blobId, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob entry by password and path
     *
     * @param path     blob path
     * @param password password to open
     * @return decrypted blob entry, see {@link Blob}
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob getBlob(String path, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob entry by privateKey and blobId
     *
     * @param blobId      blob id from 0 to (blobCount - 1)
     * @param privateKey  RSA private key to unprotect blob symmetric-key
     * @param certificate key-protection certificate
     * @return decrypted blob entry, see {@link Blob}
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob getBlob(int blobId, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get blob entry by privateKey and path
     *
     * @param path        blob path
     * @param privateKey  RSA private key to unprotect blob symmetric-key
     * @param certificate key-protection certificate
     * @return decrypted blob entry, see {@link Blob}
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Blob getBlob(String path, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * Get all tags from container
     *
     * @param password password to open container
     * @return set of tags recovered from container
     * @throws BlobfishCryptoException when cryptographic processing failed
     * @throws BlobfishDecodeException when container decoding failed
     */
    Set<String> getTags(String password) throws BlobfishCryptoException, BlobfishDecodeException;

    /**
     * Get all tags container
     *
     * @param certificate certificate to identify correct protected-key entry
     * @param privateKey  private key to decrypt protected-key entry
     * @return set of tags recovered from container
     * @throws BlobfishCryptoException when cryptographic processing failed
     * @throws BlobfishDecodeException when container decoding failed
     */
    Set<String> getTags(X509Certificate certificate, PrivateKey privateKey) throws BlobfishCryptoException, BlobfishDecodeException;

    /**
     * List childs (blob/directory) within given path
     *
     * @param path     path to look for. Path starts with `/` and ends with `/`
     * @param password to unlock container
     * @return set of directory/blob within given path. Directories ends with `/`
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Set<String> listDirectory(String path, String password) throws BlobfishDecodeException, BlobfishCryptoException;

    /**
     * List childs (blob/directory) within given path
     *
     * @param path        path to look for. Path starts with `/` and ends with `/`
     * @param certificate certificate to identify correct protected-key entry
     * @param privateKey  private key to decrypt protected-key entry
     * @return set of directory/blob within given path. Directories ends with `/`
     * @throws BlobfishDecodeException when container decoding failed
     * @throws BlobfishCryptoException when cryptographic processing failed
     */
    Set<String> listDirectory(String path, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException;
}
