package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.Blob;
import com.github.edipermadi.security.blobfish.exc.*;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.ProtocolStringList;

import java.io.IOException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.regex.Pattern;

/**
 * Container Decoder V1 implementation
 *
 * @author Edi Permadi
 */
class ContainerDecoderV1 extends ContainerDecoderBase implements ContainerDecoder {
    /**
     * Class constructor
     *
     * @param blobFish blobfish object
     */
    ContainerDecoderV1(final BlobfishProto.Blobfish blobFish) throws IOException, CertificateException {
        super(blobFish, false);
    }

    /**
     * Class constructor
     *
     * @param blobFish   blobfish object
     * @param compressed set to true to enable compression
     */
    ContainerDecoderV1(final BlobfishProto.Blobfish blobFish, final boolean compressed) throws IOException, CertificateException {
        super(blobFish, compressed);
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

        final byte[] salt = getSalt(blobFish);
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

        final byte[] salt = getSalt(blobFish);
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
    public byte[] getPayload(final int blobId, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (blobId < 0) {
            throw new IllegalArgumentException("invalid blob identifier");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password is empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        final byte[] salt = getSalt(blobFish);
        final byte[] key = deriveKey(password.toCharArray(), salt);
        return getPayload(blobId, key);
    }

    @Override
    public byte[] getPayload(final String path, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
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

        final byte[] salt = getSalt(blobFish);
        final byte[] key = deriveKey(password.toCharArray(), salt);
        return getPayload(path, key);
    }

    @Override
    public byte[] getPayload(final int blobId, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
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
                return getPayload(blobId, key);
            }
        }

        throw new InvalidDecryptionKeyException();
    }

    @Override
    public byte[] getPayload(final String path, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
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
                return getPayload(path, key);
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

        final byte[] salt = getSalt(blobFish);
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

        final byte[] salt = getSalt(blobFish);
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
            final byte[] salt = getSalt(blobFish);
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
            final byte[] salt = getSalt(blobFish);
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

    @Override
    public Set<String> listByTags(final Set<String> tags, final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (tags == null) {
            throw new IllegalArgumentException("tags is null");
        } else if (tags.isEmpty()) {
            throw new IllegalArgumentException("tags is empty");
        } else if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password ie empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        try {
            /* derive symmetric-key from password */
            final byte[] salt = getSalt(blobFish);
            final byte[] key = deriveKey(password.toCharArray(), salt);

            return listByTags(tags, key);
        } catch (final InvalidProtocolBufferException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
        }
    }

    @Override
    public Set<String> listByTags(final Set<String> tags, final X509Certificate certificate, final PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (tags == null) {
            throw new IllegalArgumentException("tags is null");
        } else if (tags.isEmpty()) {
            throw new IllegalArgumentException("tags is empty");
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

            return listByTags(tags, key);
        } catch (final InvalidProtocolBufferException ex) {
            throw new BlobfishDecodeException("failed to decode blob", ex);
        }
    }

    @Override
    public Iterator<Blob> getBlobs(final String password) throws BlobfishDecodeException, BlobfishCryptoException {
        if (password == null) {
            throw new IllegalArgumentException("password is null");
        } else if (password.isEmpty()) {
            throw new IllegalArgumentException("password ie empty");
        } else if (!blobFish.getHeader().hasPassword()) {
            throw new PasswordNotSupportedException();
        }

        /* initialize key and iv */
        final byte[] salt = getSalt(blobFish);
        final byte[] keyBytes = deriveKey(password.toCharArray(), salt);
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        /* setup iterator */
        final ListIterator<BlobfishProto.Blobfish.Body.Blob> listIterator = blobFish.getBody()
                .getBlobList()
                .listIterator();

        return new Iterator<Blob>() {
            @Override
            public boolean hasNext() {
                return listIterator.hasNext();
            }

            @Override
            public Blob next() {
                try {
                    final BlobfishProto.Blobfish.Body.Blob entry = listIterator.next();
                    final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(entry.getMetadata(), keyBytes, ivBytes);
                    final BlobfishProto.Blobfish.Body.Payload payload = decodePayload(entry.getPayload(), keyBytes, ivBytes);
                    return new BlobImpl(metadata, payload);
                } catch (final BlobfishCryptoException | BlobfishDecodeException ex) {
                    throw new RuntimeException(ex);
                }
            }

            @Override
            public void remove() {

            }
        };
    }

    @Override
    public Iterator<Blob> getBlobs(final X509Certificate certificate, PrivateKey privateKey) throws BlobfishDecodeException, BlobfishCryptoException {
        if (certificate == null) {
            throw new IllegalArgumentException("certificate is null");
        } else if (!"RSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
            throw new IllegalArgumentException("invalid certificate type");
        } else if (privateKey == null) {
            throw new IllegalArgumentException("privateKey is null");
        } else if (!"RSA".equalsIgnoreCase(privateKey.getAlgorithm())) {
            throw new IllegalArgumentException("invalid privateKey type");
        }

        final ByteString hashCertificate = digestCertificate(certificate);
        for (final BlobfishProto.Blobfish.Header.Recipient recipient : blobFish.getHeader().getRecipientList()) {
            if (hashCertificate.equals(recipient.getHashCertificate())) {
                /* setup key and iv */
                final byte[] keyBytes = unprotectKey(recipient.getCipheredKey().toByteArray(), privateKey);
                final byte[] ivBytes = new byte[16];
                Arrays.fill(ivBytes, (byte) 0);

                /* setup iterator */
                final ListIterator<BlobfishProto.Blobfish.Body.Blob> listIterator = blobFish.getBody()
                        .getBlobList()
                        .listIterator();

                return new Iterator<Blob>() {
                    @Override
                    public boolean hasNext() {
                        return listIterator.hasNext();
                    }

                    @Override
                    public Blob next() {
                        try {
                            final BlobfishProto.Blobfish.Body.Blob entry = listIterator.next();
                            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(entry.getMetadata(), keyBytes, ivBytes);
                            final BlobfishProto.Blobfish.Body.Payload payload = decodePayload(entry.getPayload(), keyBytes, ivBytes);
                            return new BlobImpl(metadata, payload);
                        } catch (final BlobfishCryptoException | BlobfishDecodeException ex) {
                            throw new RuntimeException(ex);
                        }
                    }

                    @Override
                    public void remove() {

                    }
                };
            }
        }

        throw new InvalidDecryptionKeyException();
    }

    private Blob.Metadata getMetadata(final int blobId, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            if (blob.getId() == blobId) {
                /* decrypt and decode metadata */
                final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), keyBytes, ivBytes);
                return new MetadataImpl(metadata);
            }
        }

        throw new BlobNotFoundException(blobId);
    }

    private Blob.Metadata getMetadata(final String path, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt and decode metadata */
            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), keyBytes, ivBytes);
            if (!metadata.getPath().equals(path)) {
                continue;
            }

            return new MetadataImpl(metadata);
        }

        throw new BlobNotFoundException(path);
    }

    private Blob getBlob(final int blobId, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            if (blob.getId() == blobId) {
                /* decrypt and parse metadata and payload */
                final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), keyBytes, ivBytes);
                final BlobfishProto.Blobfish.Body.Payload payload = decodePayload(blob.getPayload(), keyBytes, ivBytes);
                return new BlobImpl(metadata, payload);
            }
        }

        throw new BlobNotFoundException(blobId);
    }

    private Blob getBlob(final String path, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt metadata and payload */
            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), keyBytes, ivBytes);
            if (!metadata.getPath().equals(path)) {
                continue;
            }

            final BlobfishProto.Blobfish.Body.Payload payload = decodePayload(blob.getPayload(), keyBytes, ivBytes);
            return new BlobImpl(metadata, payload);
        }

        throw new BlobNotFoundException(path);
    }

    private byte[] getPayload(final int blobId, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            if (blob.getId() == blobId) {
                /* parse decrypted payload */
                final BlobfishProto.Blobfish.Body.Payload payload = decodePayload(blob.getPayload(), keyBytes, ivBytes);
                return payload.getData().toByteArray();
            }
        }

        throw new BlobNotFoundException(blobId);
    }

    private byte[] getPayload(final String path, final byte[] keyBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt metadata and payload */
            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), keyBytes, ivBytes);
            if (!metadata.getPath().equals(path)) {
                continue;
            }

            final BlobfishProto.Blobfish.Body.Payload payload = decodePayload(blob.getPayload(), keyBytes, ivBytes);
            return payload.getData().toByteArray();
        }

        throw new BlobNotFoundException(path);
    }

    private Set<String> getTags(final byte[] key) throws BlobfishDecodeException, BlobfishCryptoException, InvalidProtocolBufferException {
        final Set<String> result = new HashSet<>();

        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt and parse metadata */
            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), key, ivBytes);
            for (final String tag : metadata.getTagsList()) {
                result.add(tag.toLowerCase());
            }
        }

        return result;
    }

    private Set<String> listDirectory(final String path, final byte[] key) throws BlobfishDecodeException, BlobfishCryptoException, InvalidProtocolBufferException {
        final Set<String> result = new HashSet<>();

        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        final String pattern = Pattern.quote(System.getProperty("file.separator"));
        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt and parse metadata */
            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), key, ivBytes);
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

    private Set<String> listByTags(final Set<String> tags, final byte[] key) throws BlobfishDecodeException, BlobfishCryptoException, InvalidProtocolBufferException {
        final Set<String> result = new HashSet<>();

        /* initialize cipher */
        final byte[] ivBytes = new byte[16];
        Arrays.fill(ivBytes, (byte) 0);

        for (final BlobfishProto.Blobfish.Body.Blob blob : blobFish.getBody().getBlobList()) {
            /* decrypt and decode metadata */
            final BlobfishProto.Blobfish.Body.Metadata metadata = decodeMetadata(blob.getMetadata(), key, ivBytes);
            final ProtocolStringList blobTags = metadata.getTagsList();
            for (final String tag : tags) {
                if (blobTags.contains(tag)) {
                    result.add(metadata.getPath());
                }
            }
        }

        return result;
    }
}
