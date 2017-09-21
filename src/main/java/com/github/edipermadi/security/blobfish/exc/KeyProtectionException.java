package com.github.edipermadi.security.blobfish.exc;

/**
 * Key protection exception
 *
 * @author Edi Permadi
 */
public class KeyProtectionException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public KeyProtectionException(final Throwable cause) {
        super("failed to protect key", cause);
    }
}
