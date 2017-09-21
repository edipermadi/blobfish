package com.github.edipermadi.security.blobfish.exc;

/**
 * Signer setup exception
 *
 * @author Edi Permadi
 */
public final class SignerSetupException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public SignerSetupException(final Throwable cause) {
        super("failed to setup signer", cause);
    }
}
