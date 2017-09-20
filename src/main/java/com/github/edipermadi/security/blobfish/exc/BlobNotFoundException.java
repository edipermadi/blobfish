package com.github.edipermadi.security.blobfish.exc;

/**
 * Blob not found exception
 *
 * @author Edi Permadi
 */
public final class BlobNotFoundException extends BlobfishDecodeException {
    /**
     * Class constructor
     *
     * @param blobId blob identifier
     */
    public BlobNotFoundException(int blobId) {
        super("no such blob with id " + blobId);
    }
}
