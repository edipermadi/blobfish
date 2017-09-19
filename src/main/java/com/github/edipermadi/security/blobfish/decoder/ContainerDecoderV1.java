package com.github.edipermadi.security.blobfish.decoder;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Container Decoder V1 implementation
 * @author Edi Permadi
 */
public class ContainerDecoderV1 implements ContainerDecoder{
    @Override
    public int getBlobCount() {
        return 0;
    }

    @Override
    public X509Certificate getSigningCertificate() {
        return null;
    }

    @Override
    public Date getCreationDate() {
        return null;
    }

    @Override
    public Blob getBlob(int blobId, String password) throws BlobfishDecodeException {
        return null;
    }

    @Override
    public Blob getBlob(int index, PrivateKey decryptionKey) throws BlobfishDecodeException {
        return null;
    }
}
