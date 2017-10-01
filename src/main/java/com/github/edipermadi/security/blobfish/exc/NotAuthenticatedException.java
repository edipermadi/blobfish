package com.github.edipermadi.security.blobfish.exc;

/**
 * Not authenticated exception
 *
 * @author Edi Permadi
 */
public final class NotAuthenticatedException extends BlobfishDecodeException {
    /**
     * Class constructor
     */
    public NotAuthenticatedException() {
        super("signature mismatched, blob not authenticated");
    }
}
