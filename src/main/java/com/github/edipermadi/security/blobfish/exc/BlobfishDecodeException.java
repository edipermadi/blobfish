package com.github.edipermadi.security.blobfish.exc;

/**
 * Blobfish decoding base class
 *
 * @author Edi Permadi
 */
public class BlobfishDecodeException extends BlobfishException {

    /**
     * Class constructor
     *
     * @param message exception message
     */
    public BlobfishDecodeException(final String message) {
        super(message);
    }

    /**
     * Class constructor
     *
     * @param message exception message
     * @param cause   exception cause
     */
    public BlobfishDecodeException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
