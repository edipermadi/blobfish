package com.github.edipermadi.security.blobfish.exc;

/**
 * MAC setup exception
 *
 * @author Edi Permadi
 */
public final class MacSetupException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public MacSetupException(final Throwable cause) {
        super("failed to setup MAC", cause);
    }
}
