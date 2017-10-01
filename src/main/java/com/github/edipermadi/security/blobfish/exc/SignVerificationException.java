package com.github.edipermadi.security.blobfish.exc;

/**
 * Sign verification exception
 *
 * @author Edi Permadi
 */
public final class SignVerificationException extends BlobfishDecodeException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public SignVerificationException(final Throwable cause) {
        super("failed to verify signature", cause);
    }
}
