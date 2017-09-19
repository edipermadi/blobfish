package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishDecodeException;
import com.github.edipermadi.security.blobfish.exc.PasswordNotSupportedException;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Container Decoder V1 implementation
 *
 * @author Edi Permadi
 */
public class ContainerDecoderV1 extends ContainerV1Base implements ContainerDecoder {
    private final BlobfishProto.Blobfish blobFish;
    private final X509Certificate signingCertificate;

    /**
     * Class constructor
     *
     * @param blobFish blobfish object
     */
    public ContainerDecoderV1(final BlobfishProto.Blobfish blobFish) throws IOException, CertificateException {
        this.blobFish = blobFish;
        this.signingCertificate = decodeSigningCertificate(blobFish);
    }

    @Override
    public int getBlobCount() {
        return blobFish.getBody().getBlobList().size();
    }

    @Override
    public X509Certificate getSigningCertificate() {
        return signingCertificate;
    }

    @Override
    public Date getCreationDate() {
        return new Date(blobFish.getHeader().getCreated());
    }

    @Override
    public Blob getBlob(int blobId, String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        final byte[] salt = blobFish.getHeader()
                .getPassword()
                .getSalt()
                .toByteArray();
        final byte[] key = deriveKey(password.toCharArray(), salt);
        return getBlob(blobId, key);
    }

    @Override
    public Blob getBlob(int index, PrivateKey decryptionKey) throws BlobfishDecodeException {
        /* FIXME add impl */
        return null;
    }

    /**
     * Decode sender signing certificate
     *
     * @param blobFish blobfish object
     * @return sender signing certificate
     * @throws IOException          when IO failure occurred
     * @throws CertificateException when certificate cannot be recovered or invalid certificate algorithm found
     */
    private X509Certificate decodeSigningCertificate(final BlobfishProto.Blobfish blobFish) throws IOException,
            CertificateException {
        final byte[] signingCertificatePayload = blobFish.getHeader()
                .getSender()
                .getSigningCertificate()
                .toByteArray();
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(signingCertificatePayload)) {
            final CertificateFactory factory = CertificateFactory.getInstance("X.509");
            final Certificate certificate = factory.generateCertificate(bais);
            if (!"EC".equals(certificate.getPublicKey().getAlgorithm())) {
                throw new CertificateException("invalid signing certificate type");
            }
            return (X509Certificate) certificate;
        }
    }

    private Blob getBlob(final int index, final byte[] key) {
        /* FIXME add impl */
        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            final BlobfishProto.Blobfish.Body.Entry metadata = blob.getMetadata();
            final BlobfishProto.Blobfish.Body.Entry payload = blob.getPayload();
            metadata.getCiphertext();
        }

        return null;
    }
}
