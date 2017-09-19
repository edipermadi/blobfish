package com.github.edipermadi.security.blobfish.exc;

/**
 * Blobfish encoding base class
 *
 * @author Edi Permadi
 */
public abstract class BlobfishEncodeException extends BlobfishException {

    /**
     * Class constructor
     *
     * @param message exception message
     */
    public BlobfishEncodeException(final String message) {
        super(message);
    }
}
