package com.github.edipermadi.security.blobfish.exc;

/**
 * Blobfish cryptographic exception
 *
 * @author Edi Permadi
 */
public abstract class BlobfishCryptoException extends BlobfishException {
    /**
     * Class constructor
     *
     * @param message exception message
     */
    public BlobfishCryptoException(final String message) {
        super(message);
    }

    /**
     * Class constructor
     *
     * @param message exception message
     * @param cause   exception cause
     */
    public BlobfishCryptoException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
