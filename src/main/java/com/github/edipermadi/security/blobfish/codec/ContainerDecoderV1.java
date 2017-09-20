package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.*;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.io.IOUtils;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;

/**
 * Container Decoder V1 implementation
 *
 * @author Edi Permadi
 */
final class ContainerDecoderV1 extends ContainerV1Base implements ContainerDecoder {
    private final BlobfishProto.Blobfish blobFish;
    private final X509Certificate signingCertificate;

    /**
     * Class constructor
     *
     * @param blobFish blobfish object
     */
    ContainerDecoderV1(final BlobfishProto.Blobfish blobFish) throws IOException, CertificateException {
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
    public Blob getBlob(final int blobId, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if ((password == null) || password.isEmpty()) {
            throw new IllegalArgumentException("password is null/empty");
        }

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
    public Blob getBlob(final int index, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate key is null");
        } else if (!"RSA".equals(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("unexpected public key type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("private key is null");
        } else if (!"RSA".equals(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("unexpected private key type");
        }

        try {
            final MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            md.update(certificate.getPublicKey().getEncoded());
            final ByteString hashCertificate = ByteString.copyFrom(md.digest());

            final Cipher cipher = Cipher.getInstance(KEY_PROTECTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);

            for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
                if (hashCertificate.equals(recipient.getHashCertificate())) {
                    final byte[] key = cipher.doFinal(recipient.getCipheredKey().toByteArray());
                    return getBlob(index, key);
                }
            }

            throw new InvalidDecryptionKeyException();
        } catch (final NoSuchPaddingException | NoSuchAlgorithmException | InvalidKeyException | BadPaddingException | IllegalBlockSizeException ex) {
            throw new KeyUnprotectionException(ex);
        }
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

    private Blob getBlob(final int blobId, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        /* FIXME add impl */
        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            if (blob.getId() == blobId) {
                final BlobfishProto.Blobfish.Body.Entry metadataEntry = blob.getMetadata();
                final BlobfishProto.Blobfish.Body.Entry payloadEntry = blob.getPayload();
                final byte[] decryptedMetadata = decrypt(metadataEntry.getCiphertext().toByteArray(), keyBytes, ivBytes);
                final byte[] decryptedPayload = decrypt(payloadEntry.getCiphertext().toByteArray(), keyBytes, ivBytes);
                try {
                    final BlobfishProto.Blobfish.Body.Metadata metadata = BlobfishProto.Blobfish.Body.Metadata.parseFrom(decryptedMetadata);
                    final BlobfishProto.Blobfish.Body.Payload payload = BlobfishProto.Blobfish.Body.Payload.parseFrom(decryptedPayload);

                    return new Blob() {
                        @Override
                        public Metadata getMetadata() {
                            return new Metadata() {
                                @Override
                                public String getPath() {
                                    return metadata.getPath();
                                }

                                @Override
                                public Set<String> getTags() {
                                    /* extract tags */
                                    final Set<String> tags = new HashSet<>();
                                    for (int i = 0; i < metadata.getTagsCount(); i++) {
                                        tags.add(metadata.getTags(i));
                                    }
                                    return tags;
                                }

                                @Override
                                public String getMimeType() {
                                    return metadata.getMimeType();
                                }
                            };
                        }

                        @Override
                        public byte[] getPayload() {
                            return payload.getData().toByteArray();
                        }
                    };
                } catch (final InvalidProtocolBufferException ex) {
                    throw new BlobDecryptionException(ex);
                }
            }
        }

        throw new BlobNotFoundException(blobId);
    }

    /* TODO verify hmac and signature as well */
    private byte[] decrypt(final byte[] ciphertext, final byte[] keyBytes, final byte[] ivBytes) throws BlobfishCryptoException {
        try {
            final Cipher cipher = Cipher.getInstance(CIPHERING_ALGORITHM);
            final SecretKeySpec cipherKeySpec = new SecretKeySpec(keyBytes, "AES");
            final IvParameterSpec cipherIvSpec = new IvParameterSpec(ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, cipherKeySpec, cipherIvSpec);
            try (final ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
                 final CipherInputStream cis = new CipherInputStream(bais, cipher)) {
                return IOUtils.toByteArray(cis);
            }
        } catch (final IOException | NoSuchAlgorithmException | NoSuchPaddingException | InvalidAlgorithmParameterException | InvalidKeyException ex) {
            throw new BlobDecryptionException(ex);
        }
    }
}
