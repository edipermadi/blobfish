package com.github.edipermadi.security.blobfish.exc;

/**
 * Password not supported exception. Thrown when container does not support PBKDF2 based key derivation
 *
 * @author Edi Permadi
 */
public final class PasswordNotSupportedException extends BlobfishDecodeException {

    /**
     * Class constructor
     */
    public PasswordNotSupportedException() {
        super("password not supported");
    }
}
