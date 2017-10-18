package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.BlobfishEncodeException;
import com.github.edipermadi.security.blobfish.exc.KeyProtectionException;
import com.github.edipermadi.security.blobfish.exc.SignerSetupException;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import com.google.protobuf.ByteString;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.zip.GZIPOutputStream;

/**
 * Container encoder base implementation
 *
 * @author Edi Permadi
 */
abstract class ContainerEncoderBase extends ContainerBase {
    protected final PrivateKey signingPrivateKey;
    protected final int version;
    private final boolean compressed;
    protected Set<String> paths = new HashSet<>();

    /**
     * Class constructor
     *
     * @param builder    builder object
     * @param version    container encoding version
     * @param compressed set to true to enable compression
     */
    ContainerEncoderBase(final ContainerEncoderBuilder builder, final int version, final boolean compressed) {
        this.compressed = compressed;
        this.version = version;
        signingPrivateKey = builder.signingPrivateKey;
    }

    /**
     * Encode metadata into byte array
     *
     * @param path     path of blob
     * @param tags     tags of blob
     * @param mimeType mime-type of blob
     * @return serialized blob metadata
     */
    byte[] encodeMetadata(final String path, final Set<String> tags, final String mimeType) throws BlobfishEncodeException {
        final byte[] encoded = BlobfishProto.Blobfish.Body.Metadata.newBuilder()
                .setPath(path)
                .setMimeType(mimeType)
                .addAllTags(filterTags(tags))
                .build()
                .toByteArray();
        if (!compressed) {
            return encoded;
        }

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
             final GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(encoded);
            gzos.finish();
            gzos.flush();
            return baos.toByteArray();
        } catch (final IOException ex) {
            throw new BlobfishEncodeException("failed to encode metadata", ex);
        }
    }

    /**
     * Encode payload
     *
     * @param inputStream input stream of payload
     * @return byte array of encoded payload
     * @throws IOException when encoding failed
     */
    byte[] encodePayload(final InputStream inputStream) throws IOException {
        final byte[] payload = IOUtils.toByteArray(inputStream);
        final byte[] encoded = BlobfishProto.Blobfish.Body.Payload.newBuilder()
                .setData(ByteString.copyFrom(payload))
                .build()
                .toByteArray();
        if (!compressed) {
            return encoded;
        }

        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream();
             final GZIPOutputStream gzos = new GZIPOutputStream(baos)) {
            gzos.write(encoded);
            gzos.finish();
            gzos.flush();
            return baos.toByteArray();
        }
    }

    /**
     * Protect symmetric key with RSA
     *
     * @param secureRandom secure random object
     * @param keyBytes     symmetric key to be protected
     * @param certificate  symmetric-key protection certificate
     * @return byte string of protected symmetric key
     * @throws KeyProtectionException when key protection failed
     */
    ByteString protectKey(final SecureRandom secureRandom, final byte[] keyBytes, final X509Certificate certificate) throws BlobfishEncodeException {
        try {
            final Cipher cipher = Cipher.getInstance(KEY_PROTECTION_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, certificate, secureRandom);
            return ByteString.copyFrom(cipher.doFinal(keyBytes));
        } catch (final NoSuchAlgorithmException | InvalidKeyException | NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException ex) {
            throw new KeyProtectionException(ex);
        }
    }

    /**
     * Get signer object
     *
     * @param privateKey signing private key
     * @return signer object
     * @throws BlobfishCryptoException when signer setup failed
     */
    Signature getSigner(final PrivateKey privateKey) throws BlobfishCryptoException {
        try {
            final Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
            signer.initSign(privateKey);
            return signer;
        } catch (final NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new SignerSetupException(ex);
        }
    }

    /**
     * Derive salt
     *
     * @param secureRandom secure random as salt source
     * @return byte array of salt
     */
    byte[] deriveSalt(SecureRandom secureRandom) {
        final byte[] salt = new byte[32];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Convert tags to lowercase
     *
     * @param tags source tags
     * @return converted tags
     */
    private Set<String> filterTags(final Set<String> tags) {
        final Set<String> result = new HashSet<>();
        for (final String tag : tags) {
            result.add(tag.toLowerCase());
        }

        return result;
    }
}
