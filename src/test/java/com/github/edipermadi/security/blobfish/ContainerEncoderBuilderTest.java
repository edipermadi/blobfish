package com.github.edipermadi.security.blobfish;

import org.apache.commons.io.output.ByteArrayOutputStream;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Parameters;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;

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

    @Test(expectedExceptions = IllegalArgumentException.class)
    public void whenNullOutputStreamIsGivenThenExceptionThrown() {
        new ContainerEncoderBuilder()
                .setOutputStream(null);
    }

    @Parameters({"keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenSigningPrivateKeyNotSetThenBuildingThrowsException(final String senderSigningAlias,
                                                                       final String senderEncryptionAlias,
                                                                       final String recipient1EncryptionAlias,
                                                                       final String recipient2EncryptionAlias,
                                                                       final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            new ContainerEncoderBuilder()
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenSigningCertificateNotSetThenBuildingThrowsException(final String entryPassword,
                                                                        final String senderSigningAlias,
                                                                        final String senderEncryptionAlias,
                                                                        final String recipient1EncryptionAlias,
                                                                        final String recipient2EncryptionAlias,
                                                                        final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenOutputStreamNotSetThenBuildingThrowsException(final String entryPassword,
                                                                  final String senderSigningAlias,
                                                                  final String senderEncryptionAlias,
                                                                  final String recipient1EncryptionAlias,
                                                                  final String recipient2EncryptionAlias,
                                                                  final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        new ContainerEncoderBuilder()
                .setSigningKey(privateKey)
                .setSigningCertificate(senderSigningCertificate)
                .addRecipientCertificate(senderEncryptionCertificate)
                .addRecipientCertificate(recipient1EncryptionCertificate)
                .addRecipientCertificate(recipient2EncryptionCertificate)
                .setPassword(password)
                .build();
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "blobfish-password"})
    @Test(expectedExceptions = IllegalStateException.class)
    public void whenEncryptionCertificateIsEmptyThenBuildingThrowsException(final String entryPassword,
                                                                            final String senderSigningAlias,
                                                                            final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
            Assert.assertNotNull(encoder);
        }
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

    @Test
    public void whenNonNullOutputStreamIsGivenThenNoExceptionThrown() throws IOException {
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            new ContainerEncoderBuilder()
                    .setOutputStream(baos);
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2"})
    @Test
    public void whenPasswordNotSetThenBuildingCommenced(final String entryPassword,
                                                        final String senderSigningAlias,
                                                        final String senderEncryptionAlias,
                                                        final String recipient1EncryptionAlias,
                                                        final String recipient2EncryptionAlias) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setOutputStream(baos)
                    .build();
            Assert.assertNotNull(encoder);
        }
    }

    @Parameters({"keystore-entry-password",
            "keystore-alias-sig-sender",
            "keystore-alias-enc-sender",
            "keystore-alias-enc-receiver1",
            "keystore-alias-enc-receiver2",
            "blobfish-password"})
    @Test
    public void whenAllParameterSetThenBuildingCommenced(final String entryPassword,
                                                         final String senderSigningAlias,
                                                         final String senderEncryptionAlias,
                                                         final String recipient1EncryptionAlias,
                                                         final String recipient2EncryptionAlias,
                                                         final String password) throws UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException, IOException, NoSuchPaddingException, CertificateEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException {
        final PrivateKey privateKey = (PrivateKey) keyStore.getKey(senderSigningAlias, entryPassword.toCharArray());
        final X509Certificate senderSigningCertificate = (X509Certificate) keyStore.getCertificate(senderSigningAlias);
        final X509Certificate senderEncryptionCertificate = (X509Certificate) keyStore.getCertificate(senderEncryptionAlias);
        final X509Certificate recipient1EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient1EncryptionAlias);
        final X509Certificate recipient2EncryptionCertificate = (X509Certificate) keyStore.getCertificate(recipient2EncryptionAlias);
        try (final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
            final ContainerEncoder encoder = new ContainerEncoderBuilder()
                    .setSigningKey(privateKey)
                    .setSigningCertificate(senderSigningCertificate)
                    .addRecipientCertificate(senderEncryptionCertificate)
                    .addRecipientCertificate(recipient1EncryptionCertificate)
                    .addRecipientCertificate(recipient2EncryptionCertificate)
                    .setPassword(password)
                    .setOutputStream(baos)
                    .build();
            Assert.assertNotNull(encoder);
        }
    }
}
