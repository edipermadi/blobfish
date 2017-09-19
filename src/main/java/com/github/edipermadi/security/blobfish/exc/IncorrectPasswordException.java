package com.github.edipermadi.security.blobfish.exc;

/**
 * Password incorrect exception
 *
 * @author Edi Permadi
 */
public final class IncorrectPasswordException extends BlobfishDecodeException {

    /**
     * Class constructor
     */
    public IncorrectPasswordException() {
        super("password is incorrect");
    }
}
