package com.github.edipermadi.security.blobfish;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
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
    public void whenRsaSigningCertificateIsGivenThenExceptionThrown(final String keystoreAliasEncSender) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keystoreAliasEncSender);
        new ContainerEncoderBuilder()
                .setSigningCertificate(certificate);
    }

    //------------------------------------------------------------------------------------------------------------------
    // Positive Test Cases
    //------------------------------------------------------------------------------------------------------------------
    @Test
    @Parameters({"keystore-alias-sig-sender"})
    public void whenEcSigningCertificateIsGivenThenNoExceptionThrown(final String keystoreAliasEncSender) throws NoSuchAlgorithmException, KeyStoreException {
        final X509Certificate certificate = (X509Certificate) keyStore.getCertificate(keystoreAliasEncSender);
        new ContainerEncoderBuilder()
                .setSigningCertificate(certificate);
    }
}
