package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.*;
import com.google.protobuf.ByteString;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

/**
 * Container V1 base implementation
 *
 * @author Edi Permadi
 */
abstract class ContainerBase {
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String CIPHERING_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";

    static final String KEY_PROTECTION_ALGORITHM = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    static final String SIGNING_ALGORITHM = "SHA256withECDSA";

    /**
     * Perform PBKDF2 derivation from password
     *
     * @param password password input
     * @return derived key bytes
     * @throws KeyDerivationException when key derivation failed
     */
    byte[] deriveKey(final char[] password, final byte[] salt) throws KeyDerivationException {
        try {
            final PBEKeySpec spec = new PBEKeySpec(password, salt, Const.ITERATION_NUMBER, Const.KEY_LENGTH_BITS);
            final SecretKeyFactory factory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new KeyDerivationException(ex);
        }
    }

    /**
     * Digest certficate
     *
     * @param certificate certificate to be digested
     * @return byte string of certificate digest
     * @throws BlobfishCryptoException when when hashing the certificate failed
     */
    ByteString digestCertificate(final X509Certificate certificate) throws BlobfishCryptoException {
        try {
            final PublicKey publicKey = certificate.getPublicKey();
            final MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
            md.update(publicKey.getEncoded());
            return ByteString.copyFrom(md.digest());
        } catch (final NoSuchAlgorithmException ex) {
            throw new CertificateHashingException(ex);
        }
    }

    /**
     * Encode certificate
     *
     * @param certificate certificate to be encoded
     * @return byte string of serialized certificate
     * @throws BlobfishCryptoException when certificate serialization failed
     */
    ByteString encodeCertificate(final X509Certificate certificate) throws BlobfishCryptoException {
        try {
            return ByteString.copyFrom(certificate.getEncoded());
        } catch (CertificateException ex) {
            throw new CertificateSerializationException(ex);
        }
    }

    /**
     * Get MAC
     *
     * @param keyBytes byte array of symmetric key
     * @return mac object
     * @throws BlobfishCryptoException when MAC setup failed
     */
    Mac getMac(final byte[] keyBytes) throws BlobfishCryptoException {
        try {
            final SecretKeySpec macKeySpec = new SecretKeySpec(keyBytes, MAC_ALGORITHM);
            final Mac macCalculator = Mac.getInstance(MAC_ALGORITHM);
            macCalculator.init(macKeySpec);
            return macCalculator;
        } catch (final NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new MacSetupException(ex);
        }
    }

    /**
     * Get cipher for entry encryption
     *
     * @param mode     cipher mode
     * @param keyBytes byte array of symmetric key
     * @param ivBytes  byte array of initialization vector
     * @return cipher object
     * @throws BlobfishCryptoException when cipher setup failed
     */
    Cipher getCipher(final int mode, byte[] keyBytes, byte[] ivBytes) throws BlobfishCryptoException {
        try {
            final Cipher cipher = Cipher.getInstance(CIPHERING_ALGORITHM);
            final SecretKeySpec cipherKeySpec = new SecretKeySpec(keyBytes, "AES");
            final IvParameterSpec cipherIvSpec = new IvParameterSpec(ivBytes);
            cipher.init(mode, cipherKeySpec, cipherIvSpec);
            return cipher;
        } catch (final NoSuchPaddingException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new CipherSetupException(ex);
        }
    }
}
