package com.github.edipermadi.security.blobfish.codec;

import com.github.edipermadi.security.blobfish.exc.BlobfishCryptoException;
import com.github.edipermadi.security.blobfish.exc.KeyDerivationException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 * Container V1 base implementation
 *
 * @author Edi Permadi
 */
abstract class ContainerV1Base {
    static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA1";
    static final String KEY_PROTECTION_ALGORITHM = "RSA/ECB/OAEPWithSHA1AndMGF1Padding";
    static final String CIPHERING_ALGORITHM = "AES/CBC/PKCS5Padding";
    static final String SIGNING_ALGORITHM = "SHA256withECDSA";
    static final String MAC_ALGORITHM = "HmacSHA256";
    static final String HASH_ALGORITHM = "SHA-256";

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
            final byte[] key = factory.generateSecret(spec).getEncoded();
            return key;
        } catch (final NoSuchAlgorithmException | InvalidKeySpecException ex) {
            throw new KeyDerivationException(ex);
        }
    }
}
