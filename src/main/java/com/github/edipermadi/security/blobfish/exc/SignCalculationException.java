package com.github.edipermadi.security.blobfish.exc;

/**
 * Entry sign calculation exception
 *
 * @author Edi Permadi
 */
public final class SignCalculationException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public SignCalculationException(final Throwable cause) {
        super("failed to sign entry", cause);
    }
}
