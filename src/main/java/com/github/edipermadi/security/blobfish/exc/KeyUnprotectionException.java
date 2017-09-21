package com.github.edipermadi.security.blobfish.exc;

/**
 * Key unprotect exception
 *
 * @author Edi Permadi
 */
public final class KeyUnprotectionException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause cause of exception
     */
    public KeyUnprotectionException(final Throwable cause) {
        super("failed to unprotect key", cause);
    }
}
