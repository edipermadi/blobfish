package com.github.edipermadi.security.blobfish.exc;

/**
 * Blobfish Base Exception Class
 *
 * @author Edi Permadi
 */
public abstract class BlobfishException extends Exception {
    /**
     * Class constructor
     *
     * @param message exception message
     */
    public BlobfishException(final String message) {
        super(message);
    }

    /**
     * Class constructor
     *
     * @param message exception message
     * @param cause   exception cause
     */
    public BlobfishException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
