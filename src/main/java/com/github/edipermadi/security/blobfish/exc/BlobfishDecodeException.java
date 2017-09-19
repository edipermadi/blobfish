package com.github.edipermadi.security.blobfish.exc;

/**
 * Blobfish decoding base class
 *
 * @author Edi Permadi
 */
public abstract class BlobfishDecodeException extends BlobfishException {

    /**
     * Class constructor
     *
     * @param message exception message
     */
    public BlobfishDecodeException(final String message) {
        super(message);
    }
}
