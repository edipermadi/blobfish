package com.github.edipermadi.security.blobfish.exc;

public final class KeyDerivationException extends BlobfishCryptoException {
    public KeyDerivationException(final Throwable cause){
        super("failed to derive key", cause);
    }
}
