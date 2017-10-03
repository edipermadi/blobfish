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

    /**
     * Class constructor
     *
     * @param path blob path
     */
    public BlobNotFoundException(final String path) {
        super("no such blob at path '" + path + "'");
    }
}
