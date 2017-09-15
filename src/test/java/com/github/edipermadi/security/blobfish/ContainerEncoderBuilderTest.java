package com.github.edipermadi.security.blobfish;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Container Encoder Builder Unit Test
 *
 * @author Edi Permadi
 */
public final class ContainerEncoderBuilderTest extends AbstractTest {
    private KeyStore keyStore;

    @BeforeClass
    @Parameters({"keystore-file-path", "keystore-file-password"})
    public void beforeClass(final String keystoreFilePath, final String keystoreFilePassword) throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        log("using keystore file path     : %s", keystoreFilePath);
        log("using keystore file password : %s", keystoreFilePassword);

        log("loading keystore");
        this.keyStore = KeyStore.getInstance("JKS");
        try (final FileInputStream fis = new FileInputStream(new File(keystoreFilePath))) {
            keyStore.load(fis, keystoreFilePassword.toCharArray());
        }
        log("keystore loaded");
    }

    //------------------------------------------------------------------------------------------------------------------
    // Negative Test Cases
    //------------------------------------------------------------------------------------------------------------------
    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNegativeVersionIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setVersion(-1);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenZeroVersionIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setVersion(0);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullSigningCertificateIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setSigningCertificate(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    @Parameters({"keystore-alias-enc-sender"})
    public void whenRsaSigningCertificateIsGivenThenExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .setSigningCertificate(certificate);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    @Parameters({"keystore-alias-enc-sender", "keystore-entry-password"})
    public void whenRsaSigningPrivateKeyIsGivenThenExceptionThrown(final String alias, final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(alias, password.toCharArray());
        new ContainerEncoderBuilder()
                .setSigningKey(privateKey);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullEncryptionCertificateIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .addRecipientCertificate(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    @Parameters({"keystore-alias-sig-sender"})
    public void whenEcEncryptionCertificateIsGivenThenExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .addRecipientCertificate(certificate);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullPasswordIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setPassword(null);
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenEmptyPasswordIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setPassword("");
    }

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenWhitespacePasswordIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setPassword("    ");
    }

    //------------------------------------------------------------------------------------------------------------------
    // Positive Test Cases
    //------------------------------------------------------------------------------------------------------------------
    @Test
    @Parameters({"keystore-alias-sig-sender"})
    public void whenEcSigningCertificateIsGivenThenNoExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .setSigningCertificate(certificate);
    }

    @Test
    @Parameters({"keystore-alias-enc-sender"})
    public void whenRsaEncryptionCertificateIsGivenThenNoExceptionThrown(final String alias) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(alias);
        new ContainerEncoderBuilder()
                .addRecipientCertificate(certificate);
    }

    @Test
    @Parameters({"blobfish-password"})
    public void whenNonWhitespacePasswordIsGivenNoExceptionThrown(final String password) {
        new ContainerEncoderBuilder()
                .setPassword(password);
    }
}
