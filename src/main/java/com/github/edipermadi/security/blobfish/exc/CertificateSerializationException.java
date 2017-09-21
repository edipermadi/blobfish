package com.github.edipermadi.security.blobfish.exc;

/**
 * Certificate serialization exception
 *
 * @author Edi Permadi
 */
public final class CertificateSerializationException extends BlobfishCryptoException {
    /**
     * Class constructor
     *
     * @param cause exception cause
     */
    public CertificateSerializationException(final Throwable cause) {
        super("failed to serialize certificate", cause);
    }
}
