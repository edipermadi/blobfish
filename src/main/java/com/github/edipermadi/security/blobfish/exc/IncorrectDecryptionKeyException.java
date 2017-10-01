package com.github.edipermadi.security.blobfish.exc;

/**
 * Incorrect decryption key exception
 *
 * @author Edi Permadi
 */
public final class IncorrectDecryptionKeyException extends BlobfishDecodeException {
    /**
     * Class constructor
     */
    public IncorrectDecryptionKeyException() {
        super("incorrect decryption key");
    }
}
