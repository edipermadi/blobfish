package com.github.edipermadi.security.blobfish.exc;

/**
 * Invalid decryption key exception, when other than RSA private key used
 *
 * @author Edi Permadi
 */
public final class InvalidDecryptionKeyException extends BlobfishDecodeException {
    /**
     * Class constructor
     */
    public InvalidDecryptionKeyException() {
        super("invalid decryption key");
    }
}
