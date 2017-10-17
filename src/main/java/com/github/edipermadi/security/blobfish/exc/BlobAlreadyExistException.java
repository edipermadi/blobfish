package com.github.edipermadi.security.blobfish.exc;

/**
 * An exception denoting a particular path is already associated to a blob
 *
 * @author Edi Permadi
 */
public final class BlobAlreadyExistException extends BlobfishEncodeException {

    /**
     * Class constructor
     */
    public BlobAlreadyExistException() {
        super("blob already exist");
    }
}
