package com.github.edipermadi.security.blobfish.exc;

/**
 * Entry Encryption Exception
 *
 * @author Edi Permadi
 */
public final class CipherSetupException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public CipherSetupException(final Throwable cause) {
        super("failed to encrypt entry", cause);
    }
}
