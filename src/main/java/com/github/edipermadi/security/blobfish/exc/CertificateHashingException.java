package com.github.edipermadi.security.blobfish.exc;

/**
 * Certificate hashing exception
 *
 * @author Edi Permadi
 */
public final class CertificateHashingException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public CertificateHashingException(final Throwable cause) {
        super("failed to hash certificate", cause);
    }
}
