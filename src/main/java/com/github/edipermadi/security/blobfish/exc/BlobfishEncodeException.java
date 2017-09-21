package com.github.edipermadi.security.blobfish.exc;

/**
 * Blobfish encoding base class
 *
 * @author Edi Permadi
 */
public class BlobfishEncodeException extends BlobfishException {

    /**
     * Class constructor
     *
     * @param message exception message
     */
    public BlobfishEncodeException(final String message) {
        super(message);
    }

    /**
     * Class constructor
     *
     * @param message exception message
     * @param cause   exception cause
     */
    public BlobfishEncodeException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
