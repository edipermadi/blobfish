package com.github.edipermadi.security.blobfish.exc;

/**
 * Blob decryption exception
 *
 * @author Edi Permadi
 */
public final class BlobDecryptionException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public BlobDecryptionException(final Throwable cause) {
        super("failed to decrypt blob", cause);
    }
}
