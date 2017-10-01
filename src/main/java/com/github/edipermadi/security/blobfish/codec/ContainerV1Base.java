package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.*;
import com.google.protobuf.ByteString;

import javax.crypto.*;
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
abstract class ContainerV1Base {
    private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
    private static final String KEY_PROTECTION_ALGORITHM = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    private static final String CIPHERING_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SIGNING_ALGORITHM = "SHA256withECDSA";
    private static final String MAC_ALGORITHM = "HmacSHA256";
    private static final String HASH_ALGORITHM = "SHA-256";

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
     * Digest certficate
     *
     * @param certificate certificate to be digested
     * @return byte string of certificate digest
     * @throws BlobfishCryptoException when when hashing the certificate failed
     */
    ByteString digestCertificate(X509Certificate certificate) throws BlobfishCryptoException {
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
     * Encode certificate
     *
     * @param certificate certificate to be encoded
     * @return byte string of serialized certificate
     * @throws BlobfishCryptoException when certificate serialization failed
     */
    ByteString encodeCertificate(X509Certificate certificate) throws BlobfishCryptoException {
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
    Mac getMac(byte[] keyBytes) throws BlobfishCryptoException {
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
     * Get sign verifier object
     *
     * @param certificate signing certificate
     * @return sign verifier object
     * @throws BlobfishCryptoException when sign verifier setup failed
     */
    Signature getSigner(final X509Certificate certificate) throws BlobfishCryptoException {
        try {
            final Signature signer = Signature.getInstance(SIGNING_ALGORITHM);
            signer.initVerify(certificate);
            return signer;
        } catch (final NoSuchAlgorithmException | InvalidKeyException ex) {
            throw new SignerSetupException(ex);
        }
    }
}
