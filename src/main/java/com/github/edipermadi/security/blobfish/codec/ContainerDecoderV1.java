package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.*;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.io.output.ByteArrayOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.Mac;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

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
    public Blob.Metadata getMetadata(final int blobId, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (blobId < 0) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        final byte[] salt = blobFish.getHeader()
                .getPassword()
                .getSalt()
                .toByteArray();
        final byte[] key = deriveKey(password.toCharArray(), salt);
        return getMetadata(blobId, key);
    }

    @Override
    public Blob.Metadata getMetadata(final String path, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        } else if (path.isEmpty()) {
            throw new IllegalArgumentException("path is empty");
        } else if (!path.startsWith("/") || path.endsWith("/")) {
            throw new IllegalArgumentException("path is invalid");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        final byte[] salt = blobFish.getHeader()
                .getPassword()
                .getSalt()
                .toByteArray();
        final byte[] key = deriveKey(password.toCharArray(), salt);
        return getMetadata(path, key);
    }

    @Override
    public Blob.Metadata getMetadata(final int blobId, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (blobId < 0) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (certificate == null) {
            throw new IllegalArgumentException("certificate key is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("unexpected public key type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("private key is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("unexpected private key type");
        }

        final ByteString hashCertificate = digestCertificate(certificate);
        for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
            if (hashCertificate.equals(recipient.getHashCertificate())) {
                final byte[] key = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                return getMetadata(blobId, key);
            }
        }

        throw new InvalidDecryptionKeyException();
    }

    @Override
    public Blob.Metadata getMetadata(final String path, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        } else if (path.isEmpty()) {
            throw new IllegalArgumentException("path is empty");
        } else if (!path.startsWith("/") || path.endsWith("/")) {
            throw new IllegalArgumentException("path is invalid");
        } else if (certificate == null) {
            throw new IllegalArgumentException("certificate key is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("unexpected public key type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("private key is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("unexpected private key type");
        }

        final ByteString hashCertificate = digestCertificate(certificate);
        for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
            if (hashCertificate.equals(recipient.getHashCertificate())) {
                final byte[] key = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                return getMetadata(path, key);
            }
        }

        throw new InvalidDecryptionKeyException();
    }

    @Override
    public Blob getBlob(final int blobId, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (blobId < 0) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        } else if (!blobFish.getHeader().hasPassword()) {
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
    public Blob getBlob(final String path, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        } else if (path.isEmpty()) {
            throw new IllegalArgumentException("path is empty");
        } else if (!path.startsWith("/") || path.endsWith("/")) {
            throw new IllegalArgumentException("path is invalid");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        final byte[] salt = blobFish.getHeader()
                .getPassword()
                .getSalt()
                .toByteArray();
        final byte[] key = deriveKey(password.toCharArray(), salt);
        return getBlob(path, key);
    }

    @Override
    public Blob getBlob(final int blobId, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (blobId < 0) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (certificate == null) {
            throw new IllegalArgumentException("certificate key is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("unexpected public key type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("private key is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("unexpected private key type");
        }

        final ByteString hashCertificate = digestCertificate(certificate);
        for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
            if (hashCertificate.equals(recipient.getHashCertificate())) {
                final byte[] key = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                return getBlob(blobId, key);
            }
        }

        throw new InvalidDecryptionKeyException();
    }

    @Override
    public Blob getBlob(String path, X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        } else if (path.isEmpty()) {
            throw new IllegalArgumentException("path is empty");
        } else if (!path.startsWith("/") || path.endsWith("/")) {
            throw new IllegalArgumentException("path is invalid");
        } else if (certificate == null) {
            throw new IllegalArgumentException("certificate key is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("unexpected public key type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("private key is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("unexpected private key type");
        }

        final ByteString hashCertificate = digestCertificate(certificate);
        for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
            if (hashCertificate.equals(recipient.getHashCertificate())) {
                final byte[] key = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                return getBlob(path, key);
            }
        }

        throw new InvalidDecryptionKeyException();
    }

    @Override
    public Set<String> getTags(final String password) throws BlobfishCryptoException, BlobfishDecodeException {
        if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        try {
            /* derive symmetric-key from password */
            final byte[] salt = blobFish.getHeader()
                    .getPassword()
                    .getSalt()
                    .toByteArray();
            final byte[] key = deriveKey(password.toCharArray(), salt);
            return getTags(key);
        } catch (final InvalidProtocolBufferException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
        }
    }

    @Override
    public Set<String> getTags(final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishCryptoException, BlobfishDecodeException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("invalid certificate type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("privateKey is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("invalid privateKey type");
        }

        try {
            byte[] key = null;
            final ByteString hashCertificate = digestCertificate(certificate);
            for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
                if (hashCertificate.equals(recipient.getHashCertificate())) {
                    key = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                    break;
                }
            }

            /* throw when certificate does not match any */
            if (key == null) {
                throw new InvalidDecryptionKeyException();
            }

            return getTags(key);
        } catch (final InvalidProtocolBufferException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
        }
    }

    @Override
    public Set<String> listDirectory(final String path, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        } else if (path.isEmpty()) {
            throw new IllegalArgumentException("path is empty");
        } else if (!path.startsWith("/") || !path.endsWith("/")) {
            throw new IllegalArgumentException("path is invalid");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password ie empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        try {
            /* derive symmetric-key from password */
            final byte[] salt = blobFish.getHeader()
                    .getPassword()
                    .getSalt()
                    .toByteArray();
            final byte[] key = deriveKey(password.toCharArray(), salt);
            return listDirectory(path, key);
        } catch (final InvalidProtocolBufferException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
        }
    }

    @Override
    public Set<String> listDirectory(final String path, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (path == null) {
            throw new IllegalArgumentException("path is null");
        } else if (path.isEmpty()) {
            throw new IllegalArgumentException("path is empty");
        } else if (!path.startsWith("/") || !path.endsWith("/")) {
            throw new IllegalArgumentException("path is invalid");
        } else if (certificate == null) {
            throw new IllegalArgumentException("certificate is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("invalid certificate type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("privateKey is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("invalid privateKey type");
        }

        try {
            byte[] key = null;
            final ByteString hashCertificate = digestCertificate(certificate);
            for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
                if (hashCertificate.equals(recipient.getHashCertificate())) {
                    key = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                    break;
                }
            }

            /* throw when certificate does not match any */
            if (key == null) {
                throw new InvalidDecryptionKeyException();
            }

            return listDirectory(path, key);
        } catch (final InvalidProtocolBufferException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
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

    private Blob.Metadata getMetadata(final int blobId, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            if (blob.getId() == blobId) {
                /* decrypt metadata and payload */
                final byte[] decryptedMetadata = decrypt(blob.getMetadata(), keyBytes, ivBytes);

                try {
                    /* parse decrypted metadata and payload */
                    final BlobfishProto.Blobfish.Body.Metadata metadata = BlobfishProto.Blobfish.Body.Metadata.parseFrom(decryptedMetadata);

                    return new Blob.Metadata() {
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
                } catch (final InvalidProtocolBufferException ex) {
                    throw new BlobfishDecodeException("failed to decode blob", ex);
                }
            }
        }

        throw new BlobNotFoundException(blobId);
    }

    private Blob.Metadata getMetadata(final String path, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            try {
                /* decrypt metadata and payload */
                final byte[] decryptedMetadata = decrypt(blob.getMetadata(), keyBytes, ivBytes);
                final BlobfishProto.Blobfish.Body.Metadata metadata = BlobfishProto.Blobfish.Body.Metadata.parseFrom(decryptedMetadata);
                if (!metadata.getPath().equals(path)) {
                    continue;
                }

                return new Blob.Metadata() {
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
            } catch (final InvalidProtocolBufferException ex) {
                throw new BlobfishDecodeException("failed to decode blob", ex);
            }
        }

        throw new BlobNotFoundException(path);
    }

    private Blob getBlob(final int blobId, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            if (blob.getId() == blobId) {
                /* decrypt metadata and payload */
                final byte[] decryptedMetadata = decrypt(blob.getMetadata(), keyBytes, ivBytes);
                final byte[] decryptedPayload = decrypt(blob.getPayload(), keyBytes, ivBytes);

                try {
                    /* parse decrypted metadata and payload */
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
                    throw new BlobfishDecodeException("failed to decode blob", ex);
                }
            }
        }

        throw new BlobNotFoundException(blobId);
    }

    private Blob getBlob(final String path, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            try {
                /* decrypt metadata and payload */
                final byte[] decryptedMetadata = decrypt(blob.getMetadata(), keyBytes, ivBytes);
                final BlobfishProto.Blobfish.Body.Metadata metadata = BlobfishProto.Blobfish.Body.Metadata.parseFrom(decryptedMetadata);
                if (!metadata.getPath().equals(path)) {
                    continue;
                }

                final byte[] decryptedPayload = decrypt(blob.getPayload(), keyBytes, ivBytes);
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
                throw new BlobfishDecodeException("failed to decode blob", ex);
            }
        }

        throw new BlobNotFoundException(path);
    }

    /**
     * Get blob tags from container
     *
     * @param key key to unlock container
     * @return set of tags
     * @throws BlobfishDecodeException        when decoding failed
     * @throws BlobfishCryptoException        when decryption, hmac or signature verification failed
     * @throws InvalidProtocolBufferException when payload deformed
     */
    private Set<String> getTags(final byte[] key) throws BlobfishDecodeException, BlobfishCryptoException, InvalidProtocolBufferException {
        final Set<String> result = new HashSet<>();

        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt metadata */
            final byte[] decryptedMetadata = decrypt(blob.getMetadata(), key, ivBytes);

            /* parse decrypted metadata */
            final BlobfishProto.Blobfish.Body.Metadata metadata = BlobfishProto.Blobfish.Body.Metadata.parseFrom(decryptedMetadata);
            for (final String tag : metadata.getTagsList()) {
                result.add(tag.toLowerCase());
            }
        }

        return result;
    }

    /**
     * List content of directory
     *
     * @param path path to look for
     * @param key  key to unlock container
     * @return set of tags
     * @throws BlobfishDecodeException        when decoding failed
     * @throws BlobfishCryptoException        when decryption, hmac or signature verification failed
     * @throws InvalidProtocolBufferException when payload deformed
     */
    private Set<String> listDirectory(final String path, final byte[] key) throws BlobfishDecodeException, BlobfishCryptoException, InvalidProtocolBufferException {
        final Set<String> result = new HashSet<>();

        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        final String pattern = Pattern.quote(System.getProperty("file.separator"));
        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt metadata */
            final byte[] decryptedMetadata = decrypt(blob.getMetadata(), key, ivBytes);

            /* parse decrypted metadata */
            final BlobfishProto.Blobfish.Body.Metadata metadata = BlobfishProto.Blobfish.Body.Metadata.parseFrom(decryptedMetadata);
            final String entryPath = metadata.getPath();
            if (entryPath.startsWith(path)) {
                final int begin = path.length();
                final int end = entryPath.length();
                final String[] parts = entryPath.substring(begin, end).split(pattern);
                result.add(path + parts[0] + ((parts.length > 1) ? "/" : ""));
            }
        }

        return result;
    }

    /**
     * Decrypt blob entry
     *
     * @param entry    blob entry
     * @param keyBytes byte array of key
     * @param ivBytes  byte array of initialization vector
     * @return byte array of decrypted blob
     * @throws BlobfishCryptoException when decryption failed
     * @throws BlobfishDecodeException when decoding failed
     */
    private byte[] decrypt(final BlobfishProto.Blobfish.Body.Entry entry, final byte[] keyBytes, final byte[] ivBytes) throws BlobfishCryptoException, BlobfishDecodeException {
        final byte[] ciphertext = entry.getCiphertext().toByteArray();
        final byte[] hmac = entry.getHmac().toByteArray();
        final byte[] signature = entry.getSignature().toByteArray();

        try {
            /* initialize cipher */
            final Cipher cipher = getCipher(Cipher.DECRYPT_MODE, keyBytes, ivBytes);
            final Mac macCalculator = getMac(keyBytes);

            /* initialize signer */
            final Signature signer = getSigner(signingCertificate);

            final byte[] buffer = new byte[8192];
            try (final ByteArrayInputStream bais = new ByteArrayInputStream(ciphertext);
                 final ByteArrayOutputStream baos = new ByteArrayOutputStream();
                 final CipherInputStream cis = new CipherInputStream(bais, cipher)) {

                /* decrypt, update mac-calculator and signature-verifier */
                int r;
                while ((r = cis.read(buffer)) != -1) {
                    baos.write(buffer, 0, r);
                    macCalculator.update(buffer, 0, r);
                    signer.update(buffer, 0, r);
                }

                if (!Arrays.equals(macCalculator.doFinal(), hmac)) {
                    throw new IncorrectDecryptionKeyException();
                } else if (!signer.verify(signature)) {
                    throw new NotAuthenticatedException();
                }

                return baos.toByteArray();
            }
        } catch (final IOException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
        } catch (final SignatureException ex) {
            throw new SignVerificationException(ex);
        }
    }
}
