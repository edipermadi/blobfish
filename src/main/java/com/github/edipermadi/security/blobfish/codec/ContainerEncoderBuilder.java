package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishEncodeException;

import java.io.OutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Container encoder builder.
 * This class creates an instance of blobfish encoder based on given parameter
 *
 * @author Edi Permadi
 */
public final class ContainerEncoderBuilder {
    private int version = 1;
    PrivateKey signingPrivateKey;
    X509Certificate signingCertificate;
    char[] password;
    List<X509Certificate> recipientCertificates = new ArrayList<>();
    OutputStream outputStream;

    /**
     * Set encoder version
     *
     * @param version version number
     * @return this instance
     */
    public ContainerEncoderBuilder setVersion(final int version) {
        if (version < 1) {
            throw new IllegalArgumentException("invalid version number");
        }
        this.version = version;
        return this;
    }

    /**
     * Set signing certificate. Passed signing certificate should be non-null and has EC type public key
     *
     * @param signingCertificate signing certificate
     * @return this object
     */
    public ContainerEncoderBuilder setSigningCertificate(final X509Certificate signingCertificate) {
        if ((signingCertificate == null) || (!"EC".equals(signingCertificate.getPublicKey().getAlgorithm()))) {
            throw new IllegalArgumentException("invalid signing certificate");
        }

        this.signingCertificate = signingCertificate;
        return this;
    }

    public ContainerEncoderBuilder setSigningKey(final PrivateKey signingPrivateKey) {
        if ((signingPrivateKey == null) || (!"EC".equals(signingPrivateKey.getAlgorithm()))) {
            throw new IllegalArgumentException("invalid signing certificate");
        }

        this.signingPrivateKey = signingPrivateKey;
        return this;
    }

    /**
     * Set password based symmetric-key protection
     *
     * @param password password value
     * @return this instance
     */
    public ContainerEncoderBuilder setPassword(final String password) {
        if ((password == null) || password.trim().isEmpty()) {
            throw new IllegalArgumentException("invalid password");
        }
        this.password = password.toCharArray();
        return this;
    }

    /**
     * Add symmetric-key certificate based protection for recipient. Passed certificate should be non-null and has
     * RSA type public-key
     *
     * @param certificate recipient certificate
     * @return this instance
     */
    public ContainerEncoderBuilder addRecipientCertificate(final X509Certificate certificate) {
        if ((certificate == null) || (!"RSA".equals(certificate.getPublicKey().getAlgorithm()))) {
            throw new IllegalArgumentException("invalid signing certificate");
        } else if (recipientCertificates.contains(certificate)) {
            throw new IllegalArgumentException("recipient already exist");
        }

        this.recipientCertificates.add(certificate);
        return this;
    }

    /**
     * Set container output stream. Supplied output stream should be non-null
     *
     * @param outputStream output stream to store created container
     * @return this instance
     */
    public ContainerEncoderBuilder setOutputStream(final OutputStream outputStream) {
        if (outputStream == null) {
            throw new IllegalArgumentException("output-stream is null");
        }
        this.outputStream = outputStream;
        return this;
    }

    /**
     * Return container encoder object
     *
     * @return container object that implements {@link ContainerEncoder}
     * @throws BlobfishCryptoException when cryptographic failure occurred
     * @throws BlobfishEncodeException when encoding processing failed
     */
    public ContainerEncoder build() throws BlobfishCryptoException, BlobfishEncodeException {
        if (signingPrivateKey == null) {
            throw new IllegalStateException("signing private-key is mandatory");
        } else if (signingCertificate == null) {
            throw new IllegalStateException("signing certificate is mandatory");
        } else if (recipientCertificates.isEmpty()) {
            throw new IllegalStateException("recipient certificate is mandatory");
        } else if (outputStream == null) {
            throw new IllegalStateException("output-stream is mandatory");
        }

        switch (version) {
            case 1:
                return new ContainerEncoderV1(this);
            case 2:
                return new ContainerEncoderV2(this);
            default:
                throw new IllegalStateException("invalid version number");
        }
    }
}
