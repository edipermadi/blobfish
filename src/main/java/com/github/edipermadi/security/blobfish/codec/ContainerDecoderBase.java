package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.*;
import com.github.edipermadi.security.blobfish.generated.BlobfishProto;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.ByteArrayOutputStream;

import javax.crypto.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.zip.GZIPInputStream;

/**
 * Container decoder base implementation
 *
 * @author Edi Permadi
 */
abstract class ContainerDecoderBase extends ContainerBase {
    private final boolean compressed;
    final BlobfishProto.Blobfish blobFish;
    final X509Certificate signingCertificate;

    /**
     * Class constructor
     *
     * @param blobfish   blobfish object
     * @param compressed set to true to enable compression
     * @throws IOException          when reading certificate payload failed
     * @throws CertificateException when parsing certificate payload failed
     */
    ContainerDecoderBase(final BlobfishProto.Blobfish blobfish, final boolean compressed) throws IOException, CertificateException {
        if (blobfish == null) {
            throw new IllegalArgumentException("blobfish is null");
        }

        this.compressed = compressed;
        this.blobFish = blobfish;
        this.signingCertificate = decodeSigningCertificate(blobfish);
    }

    /**
     * Get salt from blobfish container
     *
     * @param blobfish blobfish container
     * @return byte array of salt
     */
    byte[] getSalt(final BlobfishProto.Blobfish blobfish) {
        return blobfish.getHeader()
                .getPassword()
                .getSalt()
                .toByteArray();
    }

    /**
     * Unprotect key
     *
     * @param protectedKey byte array of protected symmetric-key
     * @param privateKey   private key to unprotect symmetric-key
     * @return byte array of unprotected symmetric-key
     * @throws KeyUnprotectionException when unprotection failed
     */
    byte[] unprotectKey(final byte[] protectedKey, final PrivateKey privateKey) throws BlobfishDecodeException {
        try {
            final Cipher cipher = Cipher.getInstance(KEY_PROTECTION_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return cipher.doFinal(protectedKey);
        } catch (final NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException | InvalidKeyException ex) {
            throw new KeyUnprotectionException(ex);
        }
    }

    /**
     * Decode metadata
     *
     * @param entry    blob entry
     * @param keyBytes decryption key
     * @param ivBytes  cipher initial vector
     * @return metadata entry
     * @throws BlobfishDecodeException when decoding failed
     * @throws BlobfishCryptoException when crypto operation failed
     */
    BlobfishProto.Blobfish.Body.Metadata decodeMetadata(final BlobfishProto.Blobfish.Body.Entry entry,
                                                        final byte[] keyBytes, final byte[] ivBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        final byte[] decrypted = decrypt(entry, keyBytes, ivBytes, signingCertificate);
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(decrypted)) {
            if (!compressed) {
                return BlobfishProto.Blobfish.Body.Metadata.parseFrom(decrypted);
            }

            try (final GZIPInputStream gzis = new GZIPInputStream(bais)) {
                final byte[] decompressed = IOUtils.toByteArray(gzis);
                return BlobfishProto.Blobfish.Body.Metadata.parseFrom(decompressed);
            }
        } catch (final IOException ex) {
            throw new BlobfishDecodeException("failed to decode metadata", ex);
        }

    }

    /**
     * Decode payload
     *
     * @param entry    blob entry
     * @param keyBytes decryption key
     * @param ivBytes  cipher initial vector
     * @return payload entry
     * @throws BlobfishDecodeException when decoding failed
     * @throws BlobfishCryptoException when crypto operation failed
     */
    BlobfishProto.Blobfish.Body.Payload decodePayload(final BlobfishProto.Blobfish.Body.Entry entry,
                                                      final byte[] keyBytes, final byte[] ivBytes) throws BlobfishDecodeException, BlobfishCryptoException {
        final byte[] decrypted = decrypt(entry, keyBytes, ivBytes, signingCertificate);
        try (final ByteArrayInputStream bais = new ByteArrayInputStream(decrypted)) {
            if (!compressed) {
                return BlobfishProto.Blobfish.Body.Payload.parseFrom(decrypted);
            }

            try (final GZIPInputStream gzis = new GZIPInputStream(bais)) {
                return BlobfishProto.Blobfish.Body.Payload.parseFrom(gzis);
            }
        } catch (final IOException ex) {
            throw new BlobfishDecodeException("failed to decode payload", ex);
        }
    }

    /**
     * Get sign verifier object
     *
     * @param certificate signing certificate
     * @return sign verifier object
     * @throws BlobfishCryptoException when sign verifier setup failed
     */
    private Signature getSigner(final X509Certificate certificate) throws BlobfishCryptoException {
        try {
            final Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
            signer.initVerify(certificate);
            return signer;
        } catch (final NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new SignerSetupException(ex);
        }
    }

    /**
     * Decrypt blob entry
     *
     * @param entry              blob entry
     * @param keyBytes           decryption key
     * @param ivBytes            initial vector of cipher
     * @param signingCertificate signing certificate
     * @return byte array of decoded blob entry
     * @throws BlobfishCryptoException when crypto operation failed
     * @throws BlobfishDecodeException when decoding failed
     */
    private byte[] decrypt(final BlobfishProto.Blobfish.Body.Entry entry, final byte[] keyBytes, final byte[] ivBytes, final X509Certificate signingCertificate) throws BlobfishCryptoException, BlobfishDecodeException {
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
}
